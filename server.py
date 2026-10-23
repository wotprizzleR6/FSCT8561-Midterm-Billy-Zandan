from __future__ import annotations

import argparse
import getpass
import hashlib
import hmac
import ipaddress
import json
import logging
import logging.handlers
import os
import re
import secrets
import socket
import sys
import threading
import time
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

import pyotp

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import DNS, ICMP, IP, TCP, UDP, Raw, rdpcap
from scapy.error import Scapy_Exception


# Configuration
SERVER_VERSION = "Sentinel/1.0"
PROTOCOL_VERSION = 1

# localhost only
DEFAULT_HOST = "127.0.0.1"          
DEFAULT_PORT = 8888

BASE_DIR = Path(__file__).resolve().parent
USER_DB_PATH = BASE_DIR / "users.json"
AUDIT_LOG_PATH = BASE_DIR / "sentinel_audit.log"
PCAP_DIR = BASE_DIR
DEFAULT_PCAP = "FSCT8561_Operation_Sentinel_Traffic.pcap"

# Framing / resource limits against DoS
MAX_REQUEST_BYTES = 16 * 1024       # A request frame larger than this is a malformed attack
RECV_CHUNK = 4096
IDLE_TIMEOUT_S = 300                # Drop silent clients so threads are not held forever
MAX_CLIENTS = 10                    # Bounded number of concurrent handler threads
MAX_MALFORMED_PER_SESSION = 5
MAX_PCAP_BYTES = 50 * 1024 * 1024   # rdpcap() loads the whole file into memory

# Authentication policy
PBKDF2_ITERATIONS = 600_000
SALT_BYTES = 16
MIN_PASSWORD_LEN = 8
MAX_PASSWORD_LEN = 128
MAX_FAILED_PER_SESSION = 3 # From Lab 3 auth_server.py MAX_FAILED: close the connection after 3 failures
USER_LOCKOUT_THRESHOLD = 5 # Failures (across all connections) before lockout
USER_LOCKOUT_SECONDS = 120
OTP_PENDING_TTL_S = 120 # Password step must be followed by OTP within 2 min
SESSION_MAX_AGE_S = 30 * 60 # Authenticated session lifetime before re-auth
TOTP_VALID_WINDOW = 1 # Accept previous/current/next 30 s step
TOTP_ISSUER = "FSCT8561-Sentinel"

USERNAME_RE = re.compile(r"[A-Za-z0-9_.-]{1,32}")
OTP_RE = re.compile(r"\d{6}")
CMD_RE = re.compile(r"[A-Z_]{1,32}")
PCAP_NAME_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,99}\.(?:pcap|pcapng|cap)")

# Commands and role-based authorization
PUBLIC_COMMANDS = {"PING", "HELP", "LOGIN", "OTP", "EXIT"}
PROTECTED_COMMANDS = {"WHOAMI", "PCAP_ANALYZE", "DIAG", "LOGOUT"}
ROLE_PERMISSIONS = {
    "admin": {"WHOAMI", "PCAP_ANALYZE", "DIAG", "LOGOUT"},
    "analyst": {"WHOAMI", "PCAP_ANALYZE", "LOGOUT"},
}

# PCAP detection thresholds (justified in Part D)
SCAN_WINDOW_S = 10.0 
SCAN_DISTINCT_PORTS = 10
BURST_WINDOW_S = 5.0 # Unanswered SYN burst to a single service
BURST_THRESHOLD = 10
HALF_OPEN_MIN = 3
RATE_WINDOW_S = 1.0 # From Lab 4 sliding-window volume detector
RATE_THRESHOLD = 15

WELL_KNOWN_SERVICES = {20: "ftp-data", 21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http", 443: "https", 3389: "rdp"}


# From Lab 1 (server status logs) and Lab 3 (authentication attempts).
# What I added that is not from the labs: Built-in RedactingFilter regex mask, CRLF control-character
# stripping (clean()), and masking failed unknown usernames as "<unenrolled>".
# Midterm_Instructions.pdf Part D & Part E8 require security-event logging without
# recording passwords or OTPs. Python logging setup is from the Ortega textbook Ch. 1.
SENSITIVE_KEYS = {"password", "passwd", "otp", "token", "secret", "totp_secret", "code"}
_REDACT_RE = re.compile(
    r'(?i)("?(?:password|passwd|otp|token|secret|totp_secret)"?\s*[:=]\s*)("[^"]*"|\S+)'
)
_CONTROL_CHARS_RE = re.compile(r"[\x00-\x1f\x7f]")

logger = logging.getLogger("sentinel.audit")


class RedactingFilter(logging.Filter):
    """Defence in depth: even if a developer mistakenly passes a credential into
    a log message, any 'password=...', 'otp: ...' style value is masked before
    the record reaches a handler."""

    def filter(self, record: logging.LogRecord) -> bool:
        message = record.getMessage()
        redacted = _REDACT_RE.sub(r"\1[REDACTED]", message)
        if redacted != message:
            record.msg = redacted
            record.args = ()
        return True


def setup_logging() -> None:
    """Log to a rotating file (persistent audit trail) and to the console."""
    logger.setLevel(logging.INFO)
    logger.propagate = False
    if logger.handlers:
        return
    fmt = logging.Formatter("%(asctime)s | %(levelname)-7s | %(threadName)s | %(message)s")
    file_handler = logging.handlers.RotatingFileHandler(
        AUDIT_LOG_PATH, maxBytes=1_000_000, backupCount=5, encoding="utf-8"
    )
    console_handler = logging.StreamHandler(sys.stdout)
    for handler in (file_handler, console_handler):
        handler.setFormatter(fmt)
        handler.addFilter(RedactingFilter())
        logger.addHandler(handler)


def clean(value: object, max_len: int = 80) -> str:
    """Neutralise CR/LF and other control characters so a client cannot forge
    extra log lines (log injection), and bound the length of logged values."""
    text = _CONTROL_CHARS_RE.sub("?", str(value)).replace('"', "'")
    return text if len(text) <= max_len else text[:max_len] + "..."


def audit(event: str, level: int = logging.INFO, **fields: object) -> None:
    """Write one structured audit event: event=NAME key="value" ..."""
    parts = [f"event={event}"]
    for key, value in fields.items():
        if key.lower() in SENSITIVE_KEYS:
            value = "[REDACTED]"
        parts.append(f'{key}="{clean(value)}"')
    logger.log(level, " ".join(parts))


# From Lab 3 (Lab3/Codes/auth_server.py: verify_password())
# What I added that is not from the labs: Upgraded from plain SHA-256 to salted PBKDF2-HMAC-SHA256
# with a 16-byte random salt, plus hmac.compare_digest() for constant-time checks.
# The Lab 3 noted that real systems should use PBKDF2 with salts instead of
# plain SHA-256, and cryptography/hashing is covered in the Ortega textbook Ch. 14.
def hash_password(password: str, salt: bytes | None = None,
                  iterations: int = PBKDF2_ITERATIONS) -> dict:
    """Return a storable record. A unique random salt defeats precomputed /
    rainbow tables, and the iteration count makes each offline guess costly."""
    salt = salt if salt is not None else secrets.token_bytes(SALT_BYTES)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    return {"algo": "pbkdf2_sha256", "iterations": iterations,
            "salt": salt.hex(), "hash": digest.hex()}


def verify_password(password: str, record: dict) -> bool:
    """Recompute and compare in constant time (hmac.compare_digest) so response
    timing does not reveal how many leading bytes matched."""
    try:
        digest = hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"),
            bytes.fromhex(record["salt"]), int(record["iterations"])
        )
        return hmac.compare_digest(digest.hex(), record["hash"])
    except (KeyError, ValueError, TypeError):
        return False


# Dummy hash record used when a username does not exist so the server still runs PBKDF2
# and takes the same amount of time as a real user check.
DUMMY_PASSWORD_RECORD = hash_password(secrets.token_urlsafe(16))


# From Lab 3 (Lab3/Codes/auth_server.py & auth_client.py: pyotp.TOTP and random_base32())
# What I added that is not from the labs: Lab 3's totp.verify() accepts the same code multiple
# times inside the 30-second window. match_totp() returns the time-step counter so it can save
# last_otp_counter and block OTP replay. Followed instructions from Part C in the Midterm_Instructions.pdf.
def match_totp(secret: str, otp: str, valid_window: int = TOTP_VALID_WINDOW) -> int | None:
    """Return the matching TOTP time-step counter, or None.

    pyotp.TOTP.verify() only answers yes/no. We need the matched counter so the
    same code cannot be replayed inside its validity window, therefore each
    candidate step is generated and compared in constant time."""
    totp = pyotp.TOTP(secret)
    counter_now = int(time.time() // totp.interval)
    for offset in range(-valid_window, valid_window + 1):
        counter = counter_now + offset
        if hmac.compare_digest(totp.generate_otp(counter), otp):
            return counter
    return None


# From Lab 3, this replaces the hardcoded user dictionary in auth_server.py with a JSON file.
# What I added that is not from the labs: Thread-safe saving to users.json and
# consume_otp_counter() to block reusing the same 6-digit OTP code in a second session.
class UserStore:
    """Thread-safe JSON user database: {username: {role, password, totp_secret,
    last_otp_counter}}. Only password HASHES are stored."""

    def __init__(self, path: Path):
        self.path = path
        self._lock = threading.Lock()
        self._users: dict[str, dict] = {}
        self._mtime_ns: int = 0
        self.load()

    def load(self) -> None:
        if not self.path.exists():
            self._users = {}
            self._mtime_ns = 0
            return
        st = self.path.stat()
        with self.path.open("r", encoding="utf-8") as fh:
            data = json.load(fh)
        if not isinstance(data, dict):
            raise ValueError("users.json must contain a JSON object")
        self._users = data
        self._mtime_ns = st.st_mtime_ns

    def _reload_if_changed_locked(self) -> None:
        try:
            if not self.path.exists():
                return
            st = self.path.stat()
            if st.st_mtime_ns != self._mtime_ns:
                self.load()
        except (OSError, ValueError, json.JSONDecodeError):
            pass

    def _save_locked(self) -> None:
        # Atomic write: a crash mid-write cannot corrupt the credential store.
        tmp = self.path.with_suffix(".json.tmp")
        with tmp.open("w", encoding="utf-8") as fh:
            json.dump(self._users, fh, indent=2)
        os.replace(tmp, self.path)
        try:
            os.chmod(self.path, 0o600)  # Owner-only (best effort on Windows)
        except OSError:
            pass
        try:
            self._mtime_ns = self.path.stat().st_mtime_ns
        except OSError:
            pass

    def count(self) -> int:
        with self._lock:
            self._reload_if_changed_locked()
            return len(self._users)

    def get(self, username: str) -> dict | None:
        with self._lock:
            self._reload_if_changed_locked()
            record = self._users.get(username)
            return dict(record) if record else None

    def add_user(self, username: str, password: str, role: str, totp_secret: str) -> None:
        with self._lock:
            self._reload_if_changed_locked()
            self._users[username] = {
                "role": role,
                "password": hash_password(password),
                "totp_secret": totp_secret,
                "last_otp_counter": None,
                "created_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            }
            self._save_locked()

    def consume_otp_counter(self, username: str, counter: int) -> bool:
        """Atomically accept a TOTP step only if it is newer than the last one
        used. Two sessions racing with the same code cannot both succeed."""
        with self._lock:
            self._reload_if_changed_locked()
            record = self._users.get(username)
            if record is None:
                return False
            last = record.get("last_otp_counter")
            if last is not None and counter <= int(last):
                return False
            record["last_otp_counter"] = counter
            self._save_locked()
            return True


# From Lab 3, Lab3/Codes/Part 17 Code.py: MAX_FAILED = 3 attempt threshold.
# What I added that is not from the labs: Lab 3 only counted failures per connection,
# so an attacker could reconnect to get more tries. LockoutTracker counts failures
# across connections and locks the account for 120s after 5 failed attempts.
class LockoutTracker:
    """Per-account failure counter shared by all connections, so an attacker
    cannot bypass the per-session limit simply by reconnecting."""

    def __init__(self, threshold: int, lock_seconds: int):
        self.threshold = threshold
        self.lock_seconds = lock_seconds
        self._lock = threading.Lock()
        self._state: dict[str, dict] = {}

    def is_locked(self, username: str) -> bool:
        with self._lock:
            entry = self._state.get(username)
            if not entry:
                return False
            if entry["locked_until"] and time.time() < entry["locked_until"]:
                return True
            if entry["locked_until"] and time.time() >= entry["locked_until"]:
                self._state.pop(username, None)  # Lock expired
            return False

    def record_failure(self, username: str) -> bool:
        """Return True when this failure triggers a new lockout."""
        with self._lock:
            entry = self._state.setdefault(username, {"failures": 0, "locked_until": 0.0})
            entry["failures"] += 1
            if entry["failures"] >= self.threshold and not entry["locked_until"]:
                entry["locked_until"] = time.time() + self.lock_seconds
                return True
            return False

    def reset(self, username: str) -> None:
        with self._lock:
            self._state.pop(username, None)

    def locked_accounts(self) -> int:
        now = time.time()
        with self._lock:
            return sum(1 for e in self._state.values() if e["locked_until"] > now)


# From Labs 0 & 1, raw_socket/server.socket.py and challenge/server.py: sendall() and recv().
# What I added that is not from the labs: Buffers incoming bytes until the \n newline
# character instead of assuming one recv(1024) call is always one complete message.
# Based on socket methods in the Ortega textbook Ch. 3 and instructions from the Part E1 Midterm_Instructions.pdf.
class ConnectionClosed(Exception):
    """Peer closed the TCP connection (recv returned b'')."""


class FrameTooLarge(Exception):
    """Peer sent more than the allowed bytes without a frame delimiter."""


class FramedSocket:

    def __init__(self, sock: socket.socket, max_frame: int):
        self.sock = sock
        self.max_frame = max_frame
        self._buffer = bytearray()
        self._send_lock = threading.Lock()

    def send(self, obj: dict) -> None:
        data = json.dumps(obj, separators=(",", ":"), ensure_ascii=True).encode("utf-8") + b"\n"
        with self._send_lock:
            self.sock.sendall(data)

    def recv_line(self) -> bytes:
        while True:
            newline = self._buffer.find(b"\n")
            if newline != -1:
                line = bytes(self._buffer[:newline])
                del self._buffer[:newline + 1]
                if len(line) > self.max_frame:
                    raise FrameTooLarge()
                return line.rstrip(b"\r")
            if len(self._buffer) > self.max_frame:
                raise FrameTooLarge()
            chunk = self.sock.recv(RECV_CHUNK)
            if not chunk:
                raise ConnectionClosed()
            self._buffer.extend(chunk)



# Protocol helpers

class ProtocolError(Exception):
    """Raised by handlers to produce a structured ERROR response."""

    def __init__(self, code: str, message: str, close: bool = False, malformed: bool = False):
        super().__init__(message)
        self.code = code
        self.message = message
        self.close = close
        self.malformed = malformed


def make_response(status: str, code: str, message: str, data: dict | None = None) -> dict:
    return {"v": PROTOCOL_VERSION, "status": status, "code": code,
            "message": message, "data": data or {}}


def ok(code: str, message: str, data: dict | None = None) -> dict:
    return make_response("OK", code, message, data)


def error(code: str, message: str, data: dict | None = None) -> dict:
    return make_response("ERROR", code, message, data)


def check_args(args: dict, required: set[str], optional: set[str] | None = None) -> None:
    """Strict argument validation: missing or unexpected keys are rejected."""
    optional = optional or set()
    missing = required - args.keys()
    unexpected = args.keys() - required - optional
    if missing:
        raise ProtocolError("BAD_REQUEST", f"Missing argument(s): {', '.join(sorted(missing))}",
                            malformed=True)
    if unexpected:
        raise ProtocolError("BAD_REQUEST",
                            f"Unexpected argument(s): {', '.join(sorted(clean(k, 32) for k in unexpected))}",
                            malformed=True)


def parse_request(line: bytes) -> tuple[str, dict, object]:
    """Validate a raw frame and return (cmd, args, req_id)."""
    if not line.strip():
        raise ProtocolError("BAD_REQUEST", "Empty frame.", malformed=True)
    try:
        text = line.decode("utf-8")
    except UnicodeDecodeError:
        raise ProtocolError("BAD_FRAME", "Frame is not valid UTF-8.", malformed=True)
    try:
        obj = json.loads(text)
    except json.JSONDecodeError:
        raise ProtocolError("BAD_JSON", "Frame is not valid JSON.", malformed=True)
    if not isinstance(obj, dict):
        raise ProtocolError("BAD_REQUEST", "Request must be a JSON object.", malformed=True)
    unexpected = obj.keys() - {"v", "cmd", "args", "req_id"}
    if unexpected:
        raise ProtocolError("BAD_REQUEST", "Unexpected top-level field(s).", malformed=True)
    if obj.get("v", PROTOCOL_VERSION) != PROTOCOL_VERSION:
        raise ProtocolError("BAD_REQUEST", f"Unsupported protocol version (expected {PROTOCOL_VERSION}).",
                            malformed=True)
    cmd = obj.get("cmd")
    if not isinstance(cmd, str) or not CMD_RE.fullmatch(cmd.upper()):
        raise ProtocolError("BAD_REQUEST", "Field 'cmd' must be a command name.", malformed=True)
    args = obj.get("args", {})
    if not isinstance(args, dict):
        raise ProtocolError("BAD_REQUEST", "Field 'args' must be a JSON object.", malformed=True)
    req_id = obj.get("req_id")
    if req_id is not None and not (
        (isinstance(req_id, int) and not isinstance(req_id, bool))
        or (isinstance(req_id, str) and len(req_id) <= 64)
    ):
        raise ProtocolError("BAD_REQUEST", "Field 'req_id' must be an integer or short string.",
                            malformed=True)
    return cmd.upper(), args, req_id


# From Lab 4 (Lab4/Part1_Code.py to Part4_Code.py: Scapy rdpcap(), IP/TCP/UDP/ICMP layer
# filtering, Raw payload inspection, and sliding-window packet rate detection).
# What I added that is not from the labs: Two-pointer sliding window (_max_in_window) for faster time-window 
# checks. Detections for vertical port scans, SSH SYN bursts, and non-DNS traffic on UDP/53. 
# resolve_pcap() to check filenames and cap files at 50 MB.
# Taken from Lab 4 and the Ortega textbook Ch. 12 Packet analysis with Scapy.
def _utc(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat(timespec="milliseconds")


def _service_name(port: int) -> str:
    return WELL_KNOWN_SERVICES.get(port, "unknown")


def _safe_payload_sample(data: bytes, limit: int = 32) -> str:
    """Printable-ASCII preview only; never echo raw binary back to the client."""
    return "".join(chr(b) if 32 <= b < 127 else "." for b in data[:limit])


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for block in iter(lambda: fh.read(65536), b""):
            h.update(block)
    return h.hexdigest()


def _max_in_window(timestamps: list[float], window: float) -> tuple[int, int, int]:
    """Two-pointer sliding window over sorted timestamps (Lab 4 detector logic).
    Returns (max_count, left_index, right_index)."""
    best = (0, 0, -1)
    left = 0
    for right, ts in enumerate(timestamps):
        while ts - timestamps[left] > window:
            left += 1
        count = right - left + 1
        if count > best[0]:
            best = (count, left, right)
    return best


def _is_well_formed_dns(pkt) -> bool:
    """Port 53 traffic should dissect as DNS with no undecoded trailing bytes.
    Anything else on port 53 is a protocol/port mismatch."""
    if DNS not in pkt:
        return False
    dns = pkt[DNS]
    if Raw in dns:
        return False
    if dns.qr == 0 and (dns.qdcount or 0) < 1:
        return False
    return True


def analyze_pcap(path: Path) -> dict:
    """Read a capture offline with rdpcap() and return a summary plus findings.
    Every finding is an INDICATOR with evidence and a caveat - not proof."""
    started = time.perf_counter()
    packets = rdpcap(str(path))
    total = len(packets)

    protocols = Counter()
    src_counter, dst_counter = Counter(), Counter()
    service_counter, tcp_flag_counter = Counter(), Counter()
    conversations = Counter()
    per_src_times: dict[str, list[float]] = defaultdict(list)

    syn_events: list[dict] = []
    synack_keys: set[tuple] = set()
    ack_keys: set[tuple] = set()
    dns_anomalies: list[dict] = []
    dns_valid = 0

    first_ts = float(packets[0].time) if total else 0.0
    last_ts = float(packets[-1].time) if total else 0.0

    for idx, pkt in enumerate(packets):
        ts = float(pkt.time)
        first_ts, last_ts = min(first_ts, ts), max(last_ts, ts)
        if IP not in pkt:
            protocols["Non-IPv4"] += 1
            continue
        ip = pkt[IP]
        src_counter[ip.src] += 1
        dst_counter[ip.dst] += 1
        per_src_times[ip.src].append(ts)

        if TCP in pkt:
            protocols["TCP"] += 1
            tcp = pkt[TCP]
            flags = int(tcp.flags)
            syn, ack = bool(flags & 0x02), bool(flags & 0x10)
            tcp_flag_counter[str(tcp.flags)] += 1
            if syn and not ack:
                service_counter[f"TCP/{tcp.dport}"] += 1
                conversations[f"{ip.src} -> {ip.dst}:{tcp.dport}/tcp"] += 1
                syn_events.append({"idx": idx, "ts": ts, "src": ip.src, "dst": ip.dst,
                                   "sport": tcp.sport, "dport": tcp.dport})
            elif syn and ack:
                synack_keys.add((ip.dst, tcp.dport, ip.src, tcp.sport))
            elif ack:
                ack_keys.add((ip.src, tcp.sport, ip.dst, tcp.dport))
        elif UDP in pkt:
            protocols["UDP"] += 1
            udp = pkt[UDP]
            service_counter[f"UDP/{udp.dport}"] += 1
            conversations[f"{ip.src} -> {ip.dst}:{udp.dport}/udp"] += 1
            if 53 in (udp.sport, udp.dport):
                if _is_well_formed_dns(pkt):
                    dns_valid += 1
                else:
                    payload = bytes(udp.payload)
                    dns_anomalies.append({"idx": idx, "ts": ts, "src": ip.src, "dst": ip.dst,
                                          "sport": udp.sport, "dport": udp.dport,
                                          "len": len(payload),
                                          "sample": _safe_payload_sample(payload)})
        elif ICMP in pkt:
            protocols["ICMP"] += 1
        else:
            protocols["Other IPv4"] += 1

    # Mark which SYNs were answered with a SYN-ACK.
    for ev in syn_events:
        ev["answered"] = (ev["src"], ev["sport"], ev["dst"], ev["dport"]) in synack_keys
    syn_keys = {(e["src"], e["sport"], e["dst"], e["dport"]) for e in syn_events}
    completed = len(syn_keys & synack_keys & ack_keys)
    unanswered_total = sum(1 for e in syn_events if not e["answered"])

    findings: list[dict] = []
    flagged_scan_ports: set[tuple] = set()
    flagged_burst_groups: set[tuple] = set()

    # Detection 1: vertical port scan
    by_pair: dict[tuple, list[dict]] = defaultdict(list)
    for ev in syn_events:
        by_pair[(ev["src"], ev["dst"])].append(ev)
    for (src, dst), events in by_pair.items():
        events.sort(key=lambda e: e["ts"])
        port_counts: Counter = Counter()
        left, best = 0, (0, 0, -1)
        for right, ev in enumerate(events):
            port_counts[ev["dport"]] += 1
            while ev["ts"] - events[left]["ts"] > SCAN_WINDOW_S:
                old = events[left]["dport"]
                port_counts[old] -= 1
                if port_counts[old] == 0:
                    del port_counts[old]
                left += 1
            if len(port_counts) > best[0]:
                best = (len(port_counts), left, right)
        if best[0] >= SCAN_DISTINCT_PORTS:
            window = events[best[1]:best[2] + 1]
            ports = sorted({e["dport"] for e in window})
            unanswered = sum(1 for e in window if not e["answered"])
            for p in ports:
                flagged_scan_ports.add((src, dst, p))
            findings.append({
                "severity": "High",
                "category": "Port scan (vertical)",
                "source": src, "target": dst,
                "evidence": {
                    "distinct_ports": len(ports),
                    "port_range": f"{ports[0]}-{ports[-1]}",
                    "syn_packets": len(window),
                    "unanswered_syn": unanswered,
                    "duration_s": round(window[-1]["ts"] - window[0]["ts"], 3),
                    "first_packet": window[0]["idx"], "last_packet": window[-1]["idx"],
                    "first_seen_utc": _utc(window[0]["ts"]),
                },
                "rationale": (f"One source sent SYNs to {len(ports)} distinct ports on one host within "
                              f"{SCAN_WINDOW_S:.0f}s (threshold {SCAN_DISTINCT_PORTS}). Sequential "
                              f"destination ports and no completed handshakes match reconnaissance."),
                "caveat": "Could also be an authorized vulnerability scan; confirm against change records.",
            })

    # Detection 2: unanswered SYN burst against one service
    by_service: dict[tuple, list[dict]] = defaultdict(list)
    for ev in syn_events:
        if not ev["answered"]:
            by_service[(ev["src"], ev["dst"], ev["dport"])].append(ev)
    for (src, dst, dport), events in by_service.items():
        events.sort(key=lambda e: e["ts"])
        count, left, right = _max_in_window([e["ts"] for e in events], BURST_WINDOW_S)
        if count >= BURST_THRESHOLD:
            window = events[left:right + 1]
            flagged_burst_groups.add((src, dst, dport))
            findings.append({
                "severity": "Medium",
                "category": "Repeated SYN burst to single service",
                "source": src, "target": f"{dst}:{dport}/tcp ({_service_name(dport)})",
                "evidence": {
                    "unanswered_syn": count,
                    "distinct_source_ports": len({e["sport"] for e in window}),
                    "duration_s": round(window[-1]["ts"] - window[0]["ts"], 3),
                    "rate_per_s": round(count / max(window[-1]["ts"] - window[0]["ts"], 0.001), 1),
                    "first_packet": window[0]["idx"], "last_packet": window[-1]["idx"],
                    "first_seen_utc": _utc(window[0]["ts"]),
                },
                "rationale": (f"{count} new connection attempts (new source port each time) to the same "
                              f"service within {BURST_WINDOW_S:.0f}s with no SYN-ACK (threshold "
                              f"{BURST_THRESHOLD}). Consistent with SYN flooding or the start of a "
                              f"credential brute-force against {_service_name(dport).upper()}."),
                "caveat": "Only the TCP layer is visible; no authentication payloads prove brute-forcing.",
            })

    # Detection 3: residual half-open attempts
    for (src, dst, dport), events in by_service.items():
        if (src, dst, dport) in flagged_burst_groups or (src, dst, dport) in flagged_scan_ports:
            continue
        if len(events) >= HALF_OPEN_MIN:
            findings.append({
                "severity": "Low",
                "category": "Unanswered connection attempts",
                "source": src, "target": f"{dst}:{dport}/tcp ({_service_name(dport)})",
                "evidence": {
                    "unanswered_syn": len(events),
                    "duration_s": round(events[-1]["ts"] - events[0]["ts"], 3),
                    "first_packet": events[0]["idx"], "last_packet": events[-1]["idx"],
                },
                "rationale": (f"{len(events)} SYNs received no SYN-ACK in the capture. The service may be "
                              f"down/filtered, or the client is retrying an unreachable service."),
                "caveat": "Low volume; may simply reflect an incomplete capture or a stopped service.",
            })

    # Detection 4: non-DNS payload on UDP/53
    if dns_anomalies:
        by_flow: dict[tuple, list[dict]] = defaultdict(list)
        for a in dns_anomalies:
            by_flow[(a["src"], a["dst"])].append(a)
        for (src, dst), items in by_flow.items():
            findings.append({
                "severity": "Medium",
                "category": "Protocol mismatch on UDP/53 (DNS)",
                "source": src, "target": f"{dst}:53/udp",
                "evidence": {
                    "packets": len(items),
                    "distinct_source_ports": len({i["sport"] for i in items}),
                    "payload_length": sorted({i["len"] for i in items}),
                    "payload_sample": items[0]["sample"],
                    "first_packet": items[0]["idx"], "last_packet": items[-1]["idx"],
                    "first_seen_utc": _utc(items[0]["ts"]),
                },
                "rationale": ("Traffic to the DNS port that Scapy cannot dissect as DNS. Abusing port 53 "
                              "(usually allowed outbound) is a known covert-channel / tunneling technique."),
                "caveat": "Could be a misconfigured or test application; payload content alone is not malicious.",
            })

    # Detection 5: per-source packet-rate anomaly (From Lab 4 sliding window)
    peak_rates: dict[str, int] = {}
    for src, times in per_src_times.items():
        times.sort()
        count, left, right = _max_in_window(times, RATE_WINDOW_S)
        peak_rates[src] = count
        if count >= RATE_THRESHOLD:
            findings.append({
                "severity": "Low",
                "category": "High packet rate (volume anomaly)",
                "source": src, "target": "-",
                "evidence": {"packets_in_window": count, "window_s": RATE_WINDOW_S,
                             "window_start_utc": _utc(times[left])},
                "rationale": (f"Source peaked at {count} packets within {RATE_WINDOW_S:.0f}s "
                              f"(threshold {RATE_THRESHOLD}); corroborates the burst findings above."),
                "caveat": "Rate alone is weak evidence; legitimate bulk transfers can exceed it.",
            })

    severity_order = {"High": 0, "Medium": 1, "Low": 2, "Info": 3}
    findings.sort(key=lambda f: (severity_order.get(f["severity"], 9), f["category"]))
    for number, finding in enumerate(findings, start=1):
        finding["id"] = f"PCAP-{number:02d}"

    summary = {
        "file": path.name,
        "sha256": _sha256_file(path),
        "size_bytes": path.stat().st_size,
        "packet_count": total,
        "capture_start_utc": _utc(first_ts) if total else None,
        "capture_end_utc": _utc(last_ts) if total else None,
        "duration_s": round(last_ts - first_ts, 3),
        "protocols": dict(protocols),
        "unique_src_ips": len(src_counter),
        "unique_dst_ips": len(dst_counter),
        "top_sources": src_counter.most_common(5),
        "top_destinations": dst_counter.most_common(5),
        "top_services": service_counter.most_common(8),
        "top_conversations": conversations.most_common(6),
        "tcp_flags": dict(tcp_flag_counter),
        "tcp_handshake": {"syn": len(syn_events), "syn_ack": len(synack_keys),
                          "completed_handshakes": completed, "unanswered_syn": unanswered_total},
        "dns": {"well_formed": dns_valid, "malformed_on_port_53": len(dns_anomalies)},
        "peak_packets_per_source": {"window_s": RATE_WINDOW_S,
                                    "values": dict(sorted(peak_rates.items(), key=lambda kv: -kv[1]))},
        "thresholds": {"scan_ports": SCAN_DISTINCT_PORTS, "scan_window_s": SCAN_WINDOW_S,
                       "burst_syn": BURST_THRESHOLD, "burst_window_s": BURST_WINDOW_S,
                       "rate_packets": RATE_THRESHOLD, "rate_window_s": RATE_WINDOW_S},
        "analysis_time_s": round(time.perf_counter() - started, 3),
    }
    return {"summary": summary, "findings": findings,
            "disclaimer": ("Findings are traffic indicators requiring analyst review; they are not proof "
                           "of compromise. The capture is synthetic and uses documentation addresses.")}


# From Labs 1 & 3 (Lab 1 server.py command loop and Lab 3 auth_server.py two-step
# password + OTP challenge-response).
# What I added that is not from the labs: Per-thread ClientSession class so login state stays separate 
# for each connected client. Role check (authorize()) separating 'admin' and 'analyst' commands.
# Idle timeout (300s) and closing the connection after 5 bad requests.
# Based on Labs 1 & 3 and instructions from Parts A, C, and E in Midterm_Instructions.pdf.
STATE_CONNECTED = "CONNECTED"
STATE_OTP_PENDING = "OTP_PENDING"
STATE_AUTHENTICATED = "AUTHENTICATED"


class ClientSession:
    """One instance per TCP connection, running in its own thread. The
    authentication state lives here, so it can never leak between clients."""

    def __init__(self, server: "SentinelServer", sock: socket.socket, addr: tuple, session_id: int):
        self.server = server
        self.sock = sock
        self.peer = f"{addr[0]}:{addr[1]}"
        self.id = session_id
        self.conn = FramedSocket(sock, MAX_REQUEST_BYTES)
        self.state = STATE_CONNECTED
        self.pending_user: str | None = None
        self.pending_since = 0.0
        self.user: str | None = None
        self.role: str | None = None
        self.auth_time = 0.0
        self.failed_attempts = 0
        self.malformed = 0
        self.connected_at = time.time()
        self._closed = False
        self.handlers = {
            "PING": self.cmd_ping, "HELP": self.cmd_help, "LOGIN": self.cmd_login,
            "OTP": self.cmd_otp, "EXIT": self.cmd_exit, "WHOAMI": self.cmd_whoami,
            "PCAP_ANALYZE": self.cmd_pcap_analyze, "DIAG": self.cmd_diag, "LOGOUT": self.cmd_logout,
        }

    # lifecycle
    def run(self) -> None:
        audit("CONNECT", session=self.id, peer=self.peer)
        reason = "client_closed"
        try:
            self.sock.settimeout(IDLE_TIMEOUT_S)
            self.conn.send(ok("WELCOME", "Operation Sentinel server. Send HELP for commands.",
                              {"server": SERVER_VERSION, "protocol": PROTOCOL_VERSION,
                               "framing": "newline-delimited JSON",
                               "transport_encrypted": False}))
            while not self.server.stopping.is_set():
                try:
                    line = self.conn.recv_line()
                except socket.timeout:
                    self._send_quietly(make_response("BYE", "IDLE_TIMEOUT",
                                                     f"No activity for {IDLE_TIMEOUT_S}s; closing."))
                    reason = "idle_timeout"
                    break
                except FrameTooLarge:
                    self.server.stat("malformed")
                    audit("FRAME_TOO_LARGE", logging.WARNING, session=self.id, peer=self.peer,
                          limit=MAX_REQUEST_BYTES)
                    self._send_quietly(error("FRAME_TOO_LARGE",
                                             f"Request exceeds {MAX_REQUEST_BYTES} bytes; closing."))
                    reason = "oversized_frame"
                    break
                except ConnectionClosed:
                    reason = "client_closed"
                    break
                response, close, close_reason = self.dispatch(line)
                self.conn.send(response)
                if close:
                    reason = close_reason
                    break
        except (ConnectionResetError, ConnectionAbortedError, BrokenPipeError):
            reason = "connection_reset"
        except OSError:
            reason = "server_shutdown" if self.server.stopping.is_set() else "socket_error"
        except Exception as exc:  # Never let one client crash the server
            reason = "internal_error"
            audit("INTERNAL_ERROR", logging.ERROR, session=self.id, error=type(exc).__name__)
            self._send_quietly(error("INTERNAL_ERROR", "Unexpected server error."))
        finally:
            self.close()
            audit("DISCONNECT", session=self.id, peer=self.peer, user=self.user or "-",
                  reason=reason, duration_s=round(time.time() - self.connected_at, 1))

    def _send_quietly(self, response: dict) -> None:
        try:
            self.conn.send(response)
        except OSError:
            pass

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        try:
            self.sock.shutdown(socket.SHUT_RDWR)  # Clean FIN to the peer
        except OSError:
            pass
        try:
            self.sock.close()
        except OSError:
            pass

    def notify_shutdown(self) -> None:
        """Called from the main thread during server shutdown."""
        self._send_quietly(make_response("BYE", "SERVER_SHUTDOWN", "Server is shutting down."))
        try:
            self.sock.shutdown(socket.SHUT_RDWR)  # Unblocks the handler's recv()
        except OSError:
            pass

    # dispatch
    def dispatch(self, line: bytes) -> tuple[dict, bool, str]:
        req_id = None
        try:
            cmd, args, req_id = parse_request(line)
            handler = self.handlers.get(cmd)
            if handler is None:
                raise ProtocolError("UNKNOWN_COMMAND", f"Unknown command '{clean(cmd, 32)}'. Send HELP.",
                                    malformed=True)
            if cmd in PROTECTED_COMMANDS:
                self.authorize(cmd)
            response, close, reason = handler(args)
        except ProtocolError as exc:
            close, reason = exc.close, exc.code.lower()
            if exc.malformed:
                self.malformed += 1
                self.server.stat("malformed")
                audit("MALFORMED_REQUEST", logging.WARNING, session=self.id, peer=self.peer,
                      code=exc.code, count=self.malformed)
                if self.malformed >= MAX_MALFORMED_PER_SESSION:
                    close, reason = True, "too_many_malformed"
                    exc.message += " Too many malformed requests; closing connection."
            response = error(exc.code, exc.message)
        if req_id is not None:
            response["req_id"] = req_id
        return response, close, reason

    def authorize(self, cmd: str) -> None:
        """Authorization gate for every protected command."""
        if self.state != STATE_AUTHENTICATED:
            self.server.stat("denied_unauthenticated")
            audit("ACCESS_DENIED", logging.WARNING, session=self.id, peer=self.peer, cmd=cmd,
                  reason="unauthenticated", state=self.state)
            raise ProtocolError("AUTH_REQUIRED", "Authentication (password + OTP) required.")
        if time.time() - self.auth_time > SESSION_MAX_AGE_S:
            audit("SESSION_EXPIRED", session=self.id, user=self.user)
            self._reset_auth()
            raise ProtocolError("AUTH_REQUIRED", "Session expired; please log in again.")
        if cmd not in ROLE_PERMISSIONS.get(self.role or "", set()):
            self.server.stat("denied_forbidden")
            audit("ACCESS_DENIED", logging.WARNING, session=self.id, user=self.user, role=self.role,
                  cmd=cmd, reason="insufficient_role")
            raise ProtocolError("FORBIDDEN", f"Role '{self.role}' is not permitted to run {cmd}.")

    def _reset_auth(self) -> None:
        self.state = STATE_CONNECTED
        self.pending_user, self.pending_since = None, 0.0
        self.user, self.role, self.auth_time = None, None, 0.0

    # public commands
    def cmd_ping(self, args: dict):
        check_args(args, set())
        return ok("PONG", "pong", {"server_time_utc": _utc(time.time())}), False, ""

    def cmd_help(self, args: dict):
        check_args(args, set())
        commands = [
            {"cmd": "PING", "access": "public", "args": {}, "description": "Liveness check."},
            {"cmd": "HELP", "access": "public", "args": {}, "description": "List commands."},
            {"cmd": "LOGIN", "access": "public", "args": {"username": "str", "password": "str"},
             "description": "Step 1: verify password; returns OTP_REQUIRED challenge."},
            {"cmd": "OTP", "access": "public (after LOGIN)", "args": {"otp": "6 digits"},
             "description": "Step 2: verify TOTP code; grants the session."},
            {"cmd": "WHOAMI", "access": "admin, analyst", "args": {}, "description": "Session info."},
            {"cmd": "PCAP_ANALYZE", "access": "admin, analyst", "args": {"file": "optional .pcap name"},
             "description": f"Offline Scapy analysis (default {DEFAULT_PCAP})."},
            {"cmd": "DIAG", "access": "admin", "args": {}, "description": "Internal server diagnostics."},
            {"cmd": "LOGOUT", "access": "admin, analyst", "args": {}, "description": "Drop authentication."},
            {"cmd": "EXIT", "access": "public", "args": {}, "description": "Close the connection."},
        ]
        return ok("HELP", "Available commands.", {"commands": commands}), False, ""

    def cmd_exit(self, args: dict):
        check_args(args, set())
        audit("EXIT", session=self.id, user=self.user or "-")
        return make_response("BYE", "GOODBYE", "Goodbye."), True, "client_exit"

    def _auth_failure(self, known_user: str | None, stage: str, reason: str):
        """Common failure path. The client always receives the same generic
        message so it cannot tell unknown-user / wrong-password / locked apart."""
        self.failed_attempts += 1
        self.server.stat(f"{stage}_fail")
        newly_locked = False
        if known_user and reason != "account_locked":
            newly_locked = self.server.lockouts.record_failure(known_user)
        # Only enrolled usernames are logged: people often type their password
        # into the username field, so unknown usernames are never written down.
        audit("AUTH_FAIL", logging.WARNING, session=self.id, peer=self.peer, stage=stage,
              user=known_user or "<unenrolled>", reason=reason,
              attempt=f"{self.failed_attempts}/{MAX_FAILED_PER_SESSION}")
        if newly_locked:
            self.server.stat("lockouts")
            audit("ACCOUNT_LOCKED", logging.WARNING, user=known_user, seconds=USER_LOCKOUT_SECONDS)
        self._reset_auth()
        if self.failed_attempts >= MAX_FAILED_PER_SESSION:
            audit("SESSION_TERMINATED", logging.WARNING, session=self.id, peer=self.peer,
                  reason="max_failed_attempts")
            return (error("TOO_MANY_ATTEMPTS", "Too many failed attempts; connection closed."),
                    True, "max_failed_attempts")
        remaining = MAX_FAILED_PER_SESSION - self.failed_attempts
        return (error("AUTH_FAILED", "Authentication failed.", {"attempts_remaining": remaining}),
                False, "")

    def cmd_login(self, args: dict):
        check_args(args, {"username", "password"})
        if self.state == STATE_AUTHENTICATED:
            raise ProtocolError("ALREADY_AUTHENTICATED", "Already authenticated; LOGOUT first.")
        username, password = args["username"], args["password"]
        if (not isinstance(username, str) or not USERNAME_RE.fullmatch(username)
                or not isinstance(password, str) or not 1 <= len(password) <= MAX_PASSWORD_LEN):
            return self._auth_failure(None, "password", "invalid_format")

        record = self.server.users.get(username)
        if record and self.server.lockouts.is_locked(username):
            verify_password(password, DUMMY_PASSWORD_RECORD)
            return self._auth_failure(username, "password", "account_locked")
        valid = verify_password(password, record["password"] if record else DUMMY_PASSWORD_RECORD)
        del password  # Do not keep the plaintext around longer than needed
        if not record:
            return self._auth_failure(None, "password", "unknown_user")
        if not valid:
            return self._auth_failure(username, "password", "bad_password")

        self.state = STATE_OTP_PENDING
        self.pending_user, self.pending_since = username, time.time()
        self.server.stat("password_ok")
        audit("AUTH_PASSWORD_OK", session=self.id, peer=self.peer, user=username)
        return (make_response("CHALLENGE", "OTP_REQUIRED", "Password accepted. Submit your 6-digit TOTP code.",
                              {"otp_timeout_s": OTP_PENDING_TTL_S}), False, "")

    def cmd_otp(self, args: dict):
        check_args(args, {"otp"})
        if self.state != STATE_OTP_PENDING or not self.pending_user:
            raise ProtocolError("AUTH_SEQUENCE", "Submit LOGIN (password) before OTP.")
        username = self.pending_user
        if time.time() - self.pending_since > OTP_PENDING_TTL_S:
            audit("OTP_STEP_EXPIRED", session=self.id, user=username)
            self._reset_auth()
            raise ProtocolError("AUTH_SEQUENCE", "OTP step timed out; LOGIN again.")
        otp = args["otp"]
        if not isinstance(otp, str) or not OTP_RE.fullmatch(otp):
            return self._auth_failure(username, "otp", "invalid_format")
        record = self.server.users.get(username)
        if record is None or self.server.lockouts.is_locked(username):
            return self._auth_failure(username, "otp", "account_locked")

        counter = match_totp(record["totp_secret"], otp)
        del otp
        if counter is None:
            return self._auth_failure(username, "otp", "bad_otp")
        if not self.server.users.consume_otp_counter(username, counter):
            # Correct code, but already used: a replayed or sniffed OTP.
            self.server.stat("otp_replay")
            audit("OTP_REPLAY_BLOCKED", logging.WARNING, session=self.id, peer=self.peer, user=username)
            return self._auth_failure(username, "otp", "otp_replay")

        self.state = STATE_AUTHENTICATED
        self.user, self.role, self.auth_time = username, record.get("role", "analyst"), time.time()
        self.pending_user, self.pending_since = None, 0.0
        self.failed_attempts = 0
        self.server.lockouts.reset(username)
        self.server.stat("otp_ok")
        audit("AUTH_SUCCESS", session=self.id, peer=self.peer, user=username, role=self.role, mfa="totp")
        return (ok("AUTHENTICATED", f"Welcome {username}. MFA complete.",
                   {"user": username, "role": self.role,
                    "permissions": sorted(ROLE_PERMISSIONS.get(self.role, set())),
                    "session_expires_in_s": SESSION_MAX_AGE_S}), False, "")

    # protected commands
    def cmd_whoami(self, args: dict):
        check_args(args, set())
        return ok("WHOAMI", "Session information.", {
            "user": self.user, "role": self.role, "session_id": self.id, "peer": self.peer,
            "authenticated_utc": _utc(self.auth_time),
            "session_expires_in_s": max(0, int(SESSION_MAX_AGE_S - (time.time() - self.auth_time))),
        }), False, ""

    def cmd_logout(self, args: dict):
        check_args(args, set())
        audit("LOGOUT", session=self.id, user=self.user)
        self._reset_auth()
        return ok("LOGGED_OUT", "Logged out. Connection remains open."), False, ""

    def cmd_diag(self, args: dict):
        check_args(args, set())
        audit("DIAG", session=self.id, user=self.user)
        return ok("DIAG", "Server diagnostics.", self.server.diagnostics()), False, ""

    def cmd_pcap_analyze(self, args: dict):
        check_args(args, set(), {"file"})
        name = args.get("file", DEFAULT_PCAP)
        path = resolve_pcap(name)
        audit("PCAP_ANALYZE_START", session=self.id, user=self.user, file=path.name)
        try:
            result, cached = self.server.analyze_with_cache(path)
        except (Scapy_Exception, OSError, ValueError, EOFError) as exc:
            audit("PCAP_ANALYZE_FAIL", logging.ERROR, session=self.id, user=self.user,
                  file=path.name, error=type(exc).__name__)
            raise ProtocolError("PCAP_ERROR", "The capture file could not be parsed.")
        audit("PCAP_ANALYZE_DONE", session=self.id, user=self.user, file=path.name,
              packets=result["summary"]["packet_count"], findings=len(result["findings"]), cached=cached)
        return ok("PCAP_RESULT", f"Analysis of {path.name} complete.", result), False, ""


def resolve_pcap(name: object) -> Path:
    """Protecting against Path-traversal to only accept a plain file name with a capture
    extension, resolve it, and require that it sits directly inside PCAP_DIR."""
    if not isinstance(name, str) or not PCAP_NAME_RE.fullmatch(name):
        raise ProtocolError("BAD_REQUEST",
                            "Invalid file name: use a plain name ending in .pcap/.pcapng/.cap (no paths).",
                            malformed=True)
    base = PCAP_DIR.resolve()
    candidate = (base / name).resolve()
    if candidate.parent != base:
        raise ProtocolError("BAD_REQUEST", "File must be inside the server's PCAP directory.", malformed=True)
    if not candidate.is_file():
        raise ProtocolError("NOT_FOUND", f"Capture '{name}' is not available on the server.")
    if candidate.stat().st_size > MAX_PCAP_BYTES:
        raise ProtocolError("TOO_LARGE", f"Capture exceeds the {MAX_PCAP_BYTES // (1024 * 1024)} MB limit.")
    return candidate


# From Labs 0 & 1 (Lab 0 raw_socket/server.socket.py bind/listen/accept and
# Lab 1 challenge/server.py multi-threaded client handling with threading.Thread).
# What I added that is not from the labs: analyze_with_cache() so repeated PCAP_ANALYZE requests do not re-parse the same file. Clean socket 
# shutdown via shutdown(socket.SHUT_RDWR).
# Taken from Labs 0 & 1 and the Ortega textbook Ch. 2 Threading and Ch. 3 Sockets.
class SentinelServer:
    def __init__(self, host: str, port: int, users: UserStore):
        self.host, self.port = host, port
        self.users = users
        self.lockouts = LockoutTracker(USER_LOCKOUT_THRESHOLD, USER_LOCKOUT_SECONDS)
        self.stopping = threading.Event()
        self.started_at = time.time()
        self._sessions: dict[int, ClientSession] = {}
        self._sessions_lock = threading.Lock()
        self._stats: Counter = Counter()
        self._stats_lock = threading.Lock()
        self._pcap_cache: dict[tuple, dict] = {}
        self._cache_lock = threading.Lock()
        self._next_id = 0
        self._listener: socket.socket | None = None

    def stat(self, name: str, amount: int = 1) -> None:
        with self._stats_lock:
            self._stats[name] += amount

    def analyze_with_cache(self, path: Path) -> tuple[dict, bool]:
        """Re-parsing is CPU/memory heavy; caching by (path, mtime, size) stops
        an authenticated user from turning repeated requests into a DoS."""
        st = path.stat()
        key = (str(path), st.st_mtime_ns, st.st_size)
        with self._cache_lock:
            if key in self._pcap_cache:
                return self._pcap_cache[key], True
        result = analyze_pcap(path)
        with self._cache_lock:
            self._pcap_cache[key] = result
        return result, False

    def diagnostics(self) -> dict:
        with self._sessions_lock:
            sessions = [{"session_id": s.id, "peer": s.peer, "user": s.user or "-", "state": s.state,
                         "connected_s": round(time.time() - s.connected_at, 1)}
                        for s in self._sessions.values()]
        with self._stats_lock:
            stats = dict(self._stats)
        return {
            "server": SERVER_VERSION, "listen": f"{self.host}:{self.port}",
            "started_utc": _utc(self.started_at), "uptime_s": round(time.time() - self.started_at, 1),
            "active_sessions": sessions, "max_clients": MAX_CLIENTS,
            "enrolled_users": self.users.count(), "locked_accounts": self.lockouts.locked_accounts(),
            "counters": stats, "pcap_cache_entries": len(self._pcap_cache),
            "limits": {"max_request_bytes": MAX_REQUEST_BYTES, "idle_timeout_s": IDLE_TIMEOUT_S,
                       "max_failed_per_session": MAX_FAILED_PER_SESSION,
                       "lockout_threshold": USER_LOCKOUT_THRESHOLD,
                       "lockout_seconds": USER_LOCKOUT_SECONDS, "session_max_age_s": SESSION_MAX_AGE_S},
            "transport_encrypted": False,
        }

    def _create_listener(self) -> socket.socket:
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        if hasattr(socket, "SO_EXCLUSIVEADDRUSE"):
            # Windows: SO_REUSEADDR would let another process hijack the port.
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
        else:
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind((self.host, self.port))
        listener.listen(MAX_CLIENTS)
        # A short accept() timeout keeps the loop responsive to Ctrl+C on Windows.
        listener.settimeout(1.0)
        return listener

    def serve_forever(self) -> None:
        self._listener = self._create_listener()
        audit("SERVER_START", host=self.host, port=self.port, users=self.users.count(),
              pcap_dir=PCAP_DIR.name, transport="plain_tcp")
        print(f"[*] {SERVER_VERSION} listening on {self.host}:{self.port}  (Ctrl+C to stop)")
        print("[!] Transport is plain TCP (not encrypted) - localhost testing only.")
        try:
            while not self.stopping.is_set():
                try:
                    client_sock, addr = self._listener.accept()
                except socket.timeout:
                    continue
                except OSError:
                    if self.stopping.is_set():
                        break
                    raise
                self.stat("connections")
                with self._sessions_lock:
                    if len(self._sessions) >= MAX_CLIENTS:
                        self._reject_busy(client_sock, addr)
                        continue
                    self._next_id += 1
                    session = ClientSession(self, client_sock, addr, self._next_id)
                    self._sessions[session.id] = session
                threading.Thread(target=self._run_session, args=(session,),
                                 name=f"client-{session.id}", daemon=True).start()
        except KeyboardInterrupt:
            print("\n[*] Ctrl+C received - shutting down.")
        finally:
            self.shutdown()

    def _run_session(self, session: ClientSession) -> None:
        try:
            session.run()
        finally:
            with self._sessions_lock:
                self._sessions.pop(session.id, None)

    def _reject_busy(self, client_sock: socket.socket, addr: tuple) -> None:
        audit("CONNECTION_REJECTED", logging.WARNING, peer=f"{addr[0]}:{addr[1]}", reason="max_clients")
        try:
            client_sock.settimeout(2.0)
            FramedSocket(client_sock, MAX_REQUEST_BYTES).send(
                make_response("BYE", "SERVER_BUSY", "Too many concurrent clients; try later."))
            client_sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        finally:
            client_sock.close()

    def shutdown(self) -> None:
        if self.stopping.is_set() and self._listener is None:
            return
        self.stopping.set()
        if self._listener is not None:
            try:
                self._listener.close()
            except OSError:
                pass
            self._listener = None
        with self._sessions_lock:
            sessions = list(self._sessions.values())
        for session in sessions:
            session.notify_shutdown()
        deadline = time.time() + 3.0
        while time.time() < deadline:
            with self._sessions_lock:
                if not self._sessions:
                    break
            time.sleep(0.1)
        audit("SERVER_STOP", uptime_s=round(time.time() - self.started_at, 1))



# enrollment and OTP helper

def read_secret(prompt: str) -> str:
    """getpass hides typing on an interactive console; when input is piped
    (automated tests) fall back to reading a line from stdin."""
    if sys.stdin.isatty():
        return getpass.getpass(prompt)
    print(prompt, end="", flush=True)
    return sys.stdin.readline().rstrip("\r\n")


def password_policy_errors(password: str) -> list[str]:
    problems = []
    if len(password) < MIN_PASSWORD_LEN:
        problems.append(f"at least {MIN_PASSWORD_LEN} characters")
    if len(password) > MAX_PASSWORD_LEN:
        problems.append(f"at most {MAX_PASSWORD_LEN} characters")
    if not re.search(r"[A-Za-z]", password) or not re.search(r"\d", password):
        problems.append("at least one letter and one digit")
    return problems


def enroll_user(store: UserStore, username: str, role: str, force: bool) -> int:
    if not USERNAME_RE.fullmatch(username):
        print("[-] Username must be 1-32 characters: letters, digits, '_', '.', '-'.")
        return 1
    if store.get(username) and not force:
        print(f"[-] User '{username}' already exists (use --force to re-enroll).")
        return 1
    password = read_secret(f"New password for {username}: ")
    problems = password_policy_errors(password)
    if problems:
        print("[-] Password must have " + ", ".join(problems) + ".")
        return 1
    if read_secret("Confirm password: ") != password:
        print("[-] Passwords do not match.")
        return 1
    secret = pyotp.random_base32()
    store.add_user(username, password, role, secret)
    uri = pyotp.TOTP(secret).provisioning_uri(name=username, issuer_name=TOTP_ISSUER)
    print(f"[+] Enrolled '{username}' with role '{role}'. Password stored as PBKDF2 hash.")
    print("[!] Add this TOTP secret to an authenticator app NOW. It is shown only once")
    print("    on screen and is never written to the audit log.")
    print(f"    Secret : {secret}")
    print(f"    URI    : {uri}")
    audit("USER_ENROLLED", user=username, role=role)
    return 0


def show_otp(store: UserStore, username: str) -> int:
    """LAB-ONLY helper that plays the role of the user's authenticator app, so
    the system can be tested without a phone. Disable in production."""
    record = store.get(username)
    if not record:
        print(f"[-] No such user '{username}'.")
        return 1
    totp = pyotp.TOTP(record["totp_secret"])
    remaining = int(totp.interval - (time.time() % totp.interval))
    print(f"[LAB ONLY] Current OTP for {username}: {totp.now()}  (valid ~{remaining}s)")
    return 0


def validate_loopback(host: str) -> str:
    try:
        if ipaddress.ip_address(host).is_loopback:
            return host
    except ValueError:
        pass
    raise argparse.ArgumentTypeError("server may only bind to a loopback address (scope: localhost)")


def main() -> int:
    parser = argparse.ArgumentParser(description="Operation Sentinel - authenticated TCP security server")
    parser.add_argument("--host", default=DEFAULT_HOST, type=validate_loopback)
    parser.add_argument("--port", default=DEFAULT_PORT, type=int)
    parser.add_argument("--enroll", metavar="USER", help="enroll a user (prompts for password)")
    parser.add_argument("--role", choices=sorted(ROLE_PERMISSIONS), default="analyst")
    parser.add_argument("--force", action="store_true", help="overwrite an existing user on --enroll")
    parser.add_argument("--show-otp", metavar="USER", help="LAB ONLY: print the user's current TOTP code")
    args = parser.parse_args()

    if not 1 <= args.port <= 65535:
        parser.error("port must be between 1 and 65535")

    setup_logging()
    try:
        store = UserStore(USER_DB_PATH)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"[-] Could not load user database: {type(exc).__name__}")
        return 1

    if args.enroll:
        return enroll_user(store, args.enroll, args.role, args.force)
    if args.show_otp:
        return show_otp(store, args.show_otp)

    if store.count() == 0:
        print("[-] No users enrolled. Run:  python server.py --enroll <username> --role admin")
        return 1

    server = SentinelServer(args.host, args.port, store)
    try:
        server.serve_forever()
    except OSError as exc:
        print(f"[-] Could not start server on {args.host}:{args.port}: {exc}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
