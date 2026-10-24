from __future__ import annotations

import argparse
import csv
import errno
import getpass
import ipaddress
import json
import os
import re
import shutil
import socket
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from pathlib import Path
from urllib.parse import urljoin, urlsplit

import requests

try:
    import nmap
except ImportError:
    nmap = None

# Configuration
DEFAULT_SERVER_HOST = "127.0.0.1"
DEFAULT_SERVER_PORT = 8888
DEFAULT_HTTP_TARGET = "http://127.0.0.1:8765/"
DEFAULT_SCAN_START, DEFAULT_SCAN_END = 8760, 8890   # 8765 is for the website and 8888 is for the server
DEFAULT_PCAP = "FSCT8561_Operation_Sentinel_Traffic.pcap"

CONNECT_TIMEOUT_S = 5.0
REQUEST_TIMEOUT_S = 60.0
MAX_RESPONSE_BYTES = 4 * 1024 * 1024
MAX_SCAN_PORTS = 1024 # Lab 2 used <= 1000
SCAN_WORKERS = 64
SCAN_TIMEOUT_S = 2.5 if os.name == "nt" else 1.0
HTTP_TIMEOUT = (3.05, 5)          # connect, read in seconds from Lab 5 A1 to never wait forever
HTTP_PATHS = ["/", "/health", "/redirect", "/missing"]
USER_AGENT = "FSCT8561-Sentinel-Checker/1.0"

BASE_DIR = Path(__file__).resolve().parent
REPORT_DIR = BASE_DIR / "reports"
NMAP_DIRS = [r"C:\Program Files (x86)\Nmap", r"C:\Program Files\Nmap"]  # This is from Lab 2 with the path fix

USERNAME_RE = re.compile(r"[A-Za-z0-9_.-]{1,32}")
OTP_RE = re.compile(r"\d{6}")

KNOWN_LAB_SERVICES = {
    8765: "FSCT8561 test website (HTTP)",
    8888: "Sentinel server (this project)",
}

REFUSED_ERRNOS = {errno.ECONNREFUSED, 10061}
TIMEOUT_ERRNOS = {errno.ETIMEDOUT, errno.EAGAIN, errno.EWOULDBLOCK, errno.EINPROGRESS, 10035, 10060, 11, 115}


def banner(title: str) -> None:
    print(f"\n{title}\n")


def read_secret(prompt: str) -> str:
    """getpass hides typing on an interactive console (from Lab 3)"""
    if sys.stdin.isatty():
        return getpass.getpass(prompt)
    print(prompt, end="", flush=True)
    line = sys.stdin.readline()
    if not line:
        raise EOFError
    return line.rstrip("\r\n")


def prompt(text: str, default: str | None = None) -> str:
    suffix = f" [{default}]" if default is not None else ""
    value = input(f"{text}{suffix}: ").strip()
    return value if value else (default or "")


def prompt_int(text: str, default: int, low: int, high: int) -> int:
    while True:
        raw = prompt(text, str(default))
        try:
            value = int(raw)
        except ValueError:
            print(f"   '{raw}' is not a number.")
            continue
        if low <= value <= high:
            return value
        print(f"   Value must be between {low} and {high}.")


def save_csv(filename: str, rows: list[dict], fieldnames: list[str]) -> Path | None:
    """Lab 5 C6: csv.DictWriter for report evidence."""
    try:
        REPORT_DIR.mkdir(exist_ok=True)
        path = REPORT_DIR / filename
        with path.open("w", newline="", encoding="utf-8") as fh:
            writer = csv.DictWriter(fh, fieldnames=fieldnames, extrasaction="ignore")
            writer.writeheader()
            for row in rows:
                writer.writerow({k: (", ".join(map(str, v)) if isinstance(v, list) else v)
                                 for k, v in row.items()})
        return path
    except OSError as exc:
        print(f"   Could not write {filename}: {exc}")
        return None


def save_json(filename: str, data: dict) -> Path | None:
    try:
        REPORT_DIR.mkdir(exist_ok=True)
        path = REPORT_DIR / filename
        path.write_text(json.dumps(data, indent=2), encoding="utf-8")
        return path
    except OSError as exc:
        print(f"   Could not write {filename}: {exc}")
        return None


def timestamp() -> str:
    return datetime.now().strftime("%Y%m%d_%H%M%S")



# From Lab 2
#   Uses socket.gethostbyname() hostname resolution from Lab 2.
#   Other added features not in the labs 0-5: 
#   resolve_authorized_host() verifies that the resolved IP is a loopback address (ipaddress.ip_address(ip).is_loopback).
#   validate_http_target() verifies scheme, host, and bans credentials in URL. 
# Other features came from the URL validation techniques from Chapter 4 of the Ortega textbook.
class ScopeError(ValueError):
    """Raise an error if there is a non-authorized IP address entered instead of just crashing everything."""

# resolve hostname
def resolve_authorized_host(host: str) -> str:
    """From Lab 2: gethostbyname and refuse anything that is not loopback,
    so the tools cannot be pointed at third-party systems by mistake."""
    if not host:
        raise ScopeError("Target host cannot be empty.")
    try:
        ip = socket.gethostbyname(host)
    except (socket.gaierror, UnicodeError):
        raise ScopeError(f"Invalid hostname or IP address: {host!r}")
    if not ipaddress.ip_address(ip).is_loopback:
        raise ScopeError(f"{host} ({ip}) is out of scope - only localhost targets are authorized.")
    return ip


def validate_http_target(url: str) -> str:
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https"):
        raise ScopeError("URL must start with http:// or https://")
    if not parts.hostname:
        raise ScopeError("URL must include a host.")
    if parts.username or parts.password:
        raise ScopeError("Credentials in the URL are not allowed.")
    resolve_authorized_host(parts.hostname)
    return url if url.endswith("/") else url + "/"



# From Labs 0 & 1 TCP client socket
#   Raw socket initialization (socket.socket(AF_INET, SOCK_STREAM))
#   and socket.connect() from Lab 0 (raw_socket/client.socket.py) and Lab 1 (client.py).
# Other added features not in the labs 0-5:
#   A Stream Accumulator (_read_frame): Dynamic buffer reading up to '\n' to guarantee
#   full JSON frame assembly regardless of TCP segment fragmentation.
#   req_id counter pairing requests with server responses.
#   Clean TCP FIN via shutdown(socket.SHUT_RDWR).
# From textbook Ch. 3 (Socket Information Gathering).
class ServerDisconnected(Exception):
    """The server closed the connection or the socket failed."""

# Changed from data = sock.recv(1024) from Lab 0 and 1 to make it fit for TCP
class Connection:
    """Newline-delimited JSON over TCP. Buffering until '\\n' means a large
    response split over many TCP segments is still read as ONE message."""

    def __init__(self, host: str, port: int):
        self.host, self.port = host, port
        self.sock: socket.socket | None = None
        self._buffer = bytearray()
        self._req_id = 0
        self.welcome: dict | None = None

    @property
    def connected(self) -> bool:
        return self.sock is not None

    def connect(self) -> dict:
        self.close()
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(CONNECT_TIMEOUT_S)
        try:
            sock.connect((self.host, self.port))
        except OSError:
            sock.close()
            raise
        sock.settimeout(REQUEST_TIMEOUT_S)
        self.sock = sock
        self._buffer.clear()
        self.welcome = self._read_frame()            # The server greets with WELCOME
        return self.welcome

    def close(self, send_exit: bool = False) -> None:
        if self.sock is None:
            return
        if send_exit:
            try:
                self.request("EXIT")
            except (ServerDisconnected, OSError):
                pass
        if self.sock is not None:
            try:
                self.sock.shutdown(socket.SHUT_RDWR)  # Clean FIN instead of an abrupt RST
            except OSError:
                pass
            try:
                self.sock.close()
            except OSError:
                pass
        self.sock = None
        self._buffer.clear()

    def _drop(self, reason: str) -> None:
        if self.sock is not None:
            try:
                self.sock.close()
            except OSError:
                pass
        self.sock = None
        self._buffer.clear()
        raise ServerDisconnected(reason)

    def _read_frame(self) -> dict:
        assert self.sock is not None
        while True:
            newline = self._buffer.find(b"\n")
            if newline != -1:
                line = bytes(self._buffer[:newline])
                del self._buffer[:newline + 1]
                try:
                    obj = json.loads(line.decode("utf-8"))
                except (UnicodeDecodeError, json.JSONDecodeError):
                    self._drop("Server sent a malformed frame.")
                if not isinstance(obj, dict):
                    self._drop("Server sent an unexpected frame type.")
                return obj
            if len(self._buffer) > MAX_RESPONSE_BYTES:
                self._drop("Server response exceeded the size limit.")
            try:
                chunk = self.sock.recv(65536)
            except socket.timeout:
                self._drop(f"No response from server within {REQUEST_TIMEOUT_S:.0f}s.")
            except OSError as exc:
                self._drop(f"Socket error: {exc}")
            if not chunk:
                self._drop("Server closed the connection.")
            self._buffer.extend(chunk)

    def _send_bytes(self, data: bytes) -> dict:
        if self.sock is None:
            raise ServerDisconnected("Not connected to the server.")
        try:
            self.sock.sendall(data)
        except OSError as exc:
            self._drop(f"Send failed: {exc}")
        response = self._read_frame()
        if response.get("status") == "BYE":
            # Server ended the session (EXIT, idle timeout, shutdown, lockout).
            try:
                self.sock.close()
            except OSError:
                pass
            self.sock = None
            self._buffer.clear()
        return response

    def request(self, cmd: str, args: dict | None = None) -> dict:
        self._req_id += 1
        frame = {"v": 1, "cmd": cmd, "args": args or {}, "req_id": self._req_id}
        data = json.dumps(frame, separators=(",", ":")).encode("utf-8") + b"\n"
        response = self._send_bytes(data)
        if response.get("code") == "TOO_MANY_ATTEMPTS":
            self.close()
        return response

    def send_raw(self, line: str) -> dict:
        """Protocol testing: send an arbitrary line (e.g. malformed JSON)."""
        return self._send_bytes(line.encode("utf-8", errors="replace") + b"\n")


# Backwards compatibility alias
SentinelConnection = Connection



# From Lab 2 TCP PORT SCANNER
#   scan_port(): Inherits raw TCP connect_ex() from Lab 2 (Part 7 Code.py).
#   get_service(): Inherits socket.getservbyport() from Lab 2 (Part 9 Code.py).
#   run_nmap_scan(): Inherits python-nmap PortScanner & PATH resolution from Lab 2 (nmap_scanner.py).
# Other added features not in the labs 0-5:
#   A Concurrency Pool: ThreadPoolExecutor(max_workers=64) from the Ortega textbook Ch. 2, 
#   this reduces scan time from 65+ seconds down to under 3 seconds.
#   Tri-State Result Classification: Seperate open (0), closed
#   (ECONNREFUSED / WSA 10061), and filtered (ETIMEDOUT / WSA 10060).
#   Windows Winsock Tuning: Sets SCAN_TIMEOUT_S = 2.5 on Windows because Windows
#   loopback takes ~2.04s to emit WSAECONNREFUSED upon SYN retry; a 0.5s timeout
#   (from Lab 2) caused closed ports to be falsely flagged as 'filtered'.
#   Conceptual Nuance: Explicitly prints that 'open' denotes reachability,
#   not necessarily vulnerability.
# taken from Ortega textbook Ch. 2 and Microsoft Winsock TCP Stack Behavior.
def get_service(port: int) -> str:
    """Lab 2 get_service(), with labels for the known lab services."""
    if port in KNOWN_LAB_SERVICES:
        return KNOWN_LAB_SERVICES[port]
    try:
        return socket.getservbyport(port, "tcp")
    except OSError:
        return "unknown"


def scan_port(ip: str, port: int, timeout: float = SCAN_TIMEOUT_S) -> tuple[int, str]:
    """From Lab 2 Part 5 code scan_port(). I added error handling."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        result = sock.connect_ex((ip, port))
    except socket.timeout:
        result = errno.ETIMEDOUT
    except OSError as exc:
        result = exc.errno or -1
    finally:
        sock.close()
    if result == 0:
        return port, "open"
    if result in REFUSED_ERRNOS:
        return port, "closed"
    if result in TIMEOUT_ERRNOS:
        return port, "filtered"
    return port, f"error({result})"


def run_socket_scan(ip: str, start: int, end: int) -> list[tuple[int, str]]:
    """Threaded connect scan from the textbook Ch. 2 ThreadPoolExecutor. This is a bounded
    worker pool that keeps the scan fast without opening hundreds of sockets at once."""
    with ThreadPoolExecutor(max_workers=SCAN_WORKERS) as pool:
        return sorted(pool.map(lambda p: scan_port(ip, p), range(start, end + 1)))


def find_nmap() -> bool:
    if nmap is None:
        return False
    for directory in NMAP_DIRS:
        if os.path.isdir(directory) and directory not in os.environ.get("PATH", ""):
            os.environ["PATH"] = directory + os.pathsep + os.environ.get("PATH", "")
    return shutil.which("nmap") is not None


def run_nmap_scan(ip: str, start: int, end: int) -> list[tuple[int, str]]:
    """From Lab 2 nmap_scanner.py. -sT is the TCP connect scan,
    -Pn is to skip host discovery. More from the Ortega textbook Ch. 8 Scanning Networks with Nmap."""
    scanner = nmap.PortScanner()
    scanner.scan(ip, f"{start}-{end}", arguments="-sT -Pn")
    results = []
    if ip in scanner.all_hosts() and "tcp" in scanner[ip].all_protocols():
        tcp = scanner[ip]["tcp"]
        reported = {int(p): tcp[p].get("state", "unknown") for p in tcp}
    else:
        reported = {}
    for port in range(start, end + 1):
        # Nmap omits ports in its "not shown: N closed" summary.
        results.append((port, reported.get(port, "closed")))
    return results


def port_scan(target: str, start: int, end: int, engine: str = "socket") -> dict:
    if not (1 <= start <= 65535 and 1 <= end <= 65535):
        raise ValueError("Ports must be between 1 and 65535.")
    if start > end:
        raise ValueError("Start port must be less than or equal to end port.")
    if end - start + 1 > MAX_SCAN_PORTS:
        raise ValueError(f"Range too large: scan {MAX_SCAN_PORTS} ports or fewer at a time.")
    ip = resolve_authorized_host(target)
    began = time.perf_counter()
    results = run_nmap_scan(ip, start, end) if engine == "nmap" else run_socket_scan(ip, start, end)
    duration = round(time.perf_counter() - began, 2)
    states: dict[str, int] = {}
    for _, state in results:
        states[state] = states.get(state, 0) + 1
    return {
        "target": target, "ip": ip, "range": f"{start}-{end}", "engine": engine,
        "duration_s": duration, "states": states,
        "open": [{"port": p, "state": s, "service": get_service(p)} for p, s in results if s == "open"],
        "results": [{"port": p, "state": s, "service": get_service(p)} for p, s in results],
        "time": datetime.now().isoformat(timespec="seconds"),
    }


def print_scan_report(report: dict, server_port: int) -> None:
    banner(f"Port scan: {report['ip']} TCP {report['range']} ({report['engine']} engine)")
    print(f"{'PORT':<8}{'STATE':<10}SERVICE")
    for item in report["open"]:
        print(f"{item['port']:<8}{item['state']:<10}{item['service']}")
    if not report["open"]:
        print("(no open ports in range)")
    summary = ", ".join(f"{k}={v}" for k, v in sorted(report["states"].items()))
    print(f"Scanned {len(report['results'])} ports in {report['duration_s']}s  ->  {summary}")
    open_ports = {i["port"] for i in report["open"]}
    lo, hi = map(int, report["range"].split("-"))
    if lo <= server_port <= hi:
        state = "OPEN" if server_port in open_ports else "NOT open"
        print(f"Sentinel server port {server_port}: {state}")
    closed_example = next((i["port"] for i in report["results"] if i["state"] == "closed"), None)
    if closed_example is not None:
        print(f"Example closed port: {closed_example} (connection refused - nothing listening)")
    print("\nNOTE: 'open' means the port is REACHABLE (TCP handshake completed). It does not")
    print("      mean the service is vulnerable; each open service needs its own assessment.")



# From Labs 0-5:
#   requests.get(): Inherits HTTP probing and connect/read timeouts from Lab 5.
#   Header Baselines: Inherits inspection of Content-Security-Policy and
#   X-Content-Type-Options: nosniff from Lab 5 (Lab5.ipynb).
#   Finding De-duplication: Inherits set() de-duplication principle from Lab 5.
#   CSV Export: Inherits csv.DictWriter export pattern from Lab 5.
# Other added features not in the labs 0-5:
#   FindingSet Class: Aggregates repeated baseline gaps across multiple endpoints
#   under a single finding ID (inspired by commercial scanners like Nessus/OpenVAS).
#   Deep Cookie Attribute Auditing: Uses raw urllib3 header lists to inspect
#   each Set-Cookie header individually for HttpOnly, SameSite, and Secure flags.
#   Redirect Inspection: Uses allow_redirects=False to inspect 301/302 responses
#   for HTTPS->HTTP downgrade or off-site open redirects.
#   Error Content Fingerprinting: Scans 4xx/5xx responses for internal debug leaks
#   (traceback, werkzeug, sqlite).
#   Core Conceptual Nuance: Stamped with REVIEW_STATUS ("Configuration review -
#   not proof of exploitability"). A missing header weakened defense-in-depth,
#   but does not constitute an active exploitable vulnerability on its own.
# Source: Lab 5 Guidelines and Ortega textbook Ch. 4 and Ch. 10.
REVIEW_STATUS = "Configuration review - not proof of exploitability"

HTML_HEADERS = {
    "Content-Security-Policy": (
        "Medium",
        "No CSP: the browser has no allow-list restricting script/style sources, so any "
        "injection flaw would be easier to turn into XSS.",
        "Add a restrictive Content-Security-Policy (e.g. default-src 'self').",
    ),
    "X-Frame-Options": (
        "Low",
        "No framing restriction (X-Frame-Options or CSP frame-ancestors): pages could be embedded "
        "by another site (clickjacking).",
        "Send X-Frame-Options: DENY or CSP frame-ancestors 'none'.",
    ),
    "Referrer-Policy": (
        "Low",
        "No Referrer-Policy: full URLs may leak to other origins via the Referer header.",
        "Send Referrer-Policy: strict-origin-when-cross-origin (or no-referrer).",
    ),
}
ALL_RESPONSE_HEADERS = {
    "X-Content-Type-Options": (
        "Low",
        "No 'nosniff': browsers may MIME-sniff responses and interpret them as a different type.",
        "Send X-Content-Type-Options: nosniff on every response.",
    ),
}
VERBOSE_ERROR_MARKERS = ["traceback", "stack trace", "exception", "sqlite", "werkzeug", "debug", "at line", "syntax error"]


class FindingSet:
    """De-duplicated findings (Lab 5 C5 'seen' set). The same issue on several
    endpoints becomes ONE finding listing every affected endpoint."""

    def __init__(self) -> None:
        self._items: dict[tuple, dict] = {}

    def add(self, severity: str, category: str, endpoint: str, observation: str,
            why: str, recommendation: str, status: str = REVIEW_STATUS) -> None:
        key = (category, observation)
        if key in self._items:
            if endpoint not in self._items[key]["endpoints"]:
                self._items[key]["endpoints"].append(endpoint)
            return
        self._items[key] = {"severity": severity, "category": category, "endpoints": [endpoint],
                            "observation": observation, "why_it_matters": why,
                            "recommendation": recommendation, "status": status}

    def as_list(self) -> list[dict]:
        order = {"High": 0, "Medium": 1, "Low": 2, "Info": 3}
        items = sorted(self._items.values(), key=lambda f: (order.get(f["severity"], 9), f["category"]))
        for number, item in enumerate(items, start=1):
            item["id"] = f"HTTP-{number:02d}"
        return items


def _set_cookie_values(response: requests.Response) -> list[str]:
    """requests folds multiple Set-Cookie headers into one string; read the raw
    urllib3 header list when available so each cookie is inspected separately."""
    raw_headers = getattr(response.raw, "headers", None)
    if raw_headers is not None and hasattr(raw_headers, "getlist"):
        values = raw_headers.getlist("Set-Cookie")
        if values:
            return list(values)
    value = response.headers.get("Set-Cookie")
    return [value] if value else []


def _analyze_response(url: str, path: str, response: requests.Response, findings: FindingSet, positives: list[str]) -> None:
    headers = response.headers  # Case-insensitive dict
    content_type = headers.get("Content-Type", "")
    is_html = "text/html" in content_type.lower()
    status = response.status_code

    # Security headers - relevance depends on the response type (Lab 5 C4).
    if response.content:
        for name, (sev, why, fix) in ALL_RESPONSE_HEADERS.items():
            if name not in headers:
                findings.add(sev, "Missing security header", path, f"{name} not set", why, fix)
            else:
                positives.append(f"{path}: {name} present ({headers[name]})")
    if is_html:
        csp = headers.get("Content-Security-Policy", "")
        for name, (sev, why, fix) in HTML_HEADERS.items():
            if name == "X-Frame-Options" and "frame-ancestors" in csp.lower():
                continue
            if name not in headers:
                findings.add(sev, "Missing security header", path, f"{name} not set", why, fix)
            else:
                positives.append(f"{path}: {name} present")

    # Implementation disclosure (Lab 5: Server header is informational).
    server = headers.get("Server")
    if server:
        findings.add("Info", "Information disclosure", path, f"Server header discloses '{server}'",
                     "Reveals software name/version that helps an attacker fingerprint the stack; "
                     "not a vulnerability by itself.",
                     "Suppress or genericise the Server banner.")
    powered = headers.get("X-Powered-By")
    if powered:
        findings.add("Info", "Information disclosure", path, f"X-Powered-By discloses '{powered}'",
                     "Reveals framework details useful for fingerprinting.", "Remove X-Powered-By.")

    # Cookie attributes.
    for cookie in _set_cookie_values(response):
        name = cookie.split("=", 1)[0].strip()
        attrs = {part.strip().split("=", 1)[0].lower() for part in cookie.split(";")[1:]}
        if "httponly" not in attrs:
            findings.add("Medium", "Cookie attributes", path, f"Cookie '{name}' lacks HttpOnly",
                         "JavaScript can read the cookie, so any XSS could steal the session value.",
                         "Set HttpOnly on session cookies.")
        if "samesite" not in attrs:
            findings.add("Low", "Cookie attributes", path, f"Cookie '{name}' lacks SameSite",
                         "Browser default applies; explicit SameSite reduces cross-site request risk.",
                         "Set SameSite=Lax or Strict.")
        if "secure" not in attrs:
            findings.add("Low", "Cookie attributes", path, f"Cookie '{name}' lacks Secure",
                         "The cookie may be sent over plaintext HTTP where it can be sniffed.",
                         "Serve over HTTPS and set Secure.")

    # Redirect behaviour (requests was told NOT to follow redirects).
    if 300 <= status < 400:
        location = headers.get("Location")
        if not location:
            findings.add("Low", "Redirect handling", path, f"{status} redirect without Location header",
                         "Malformed redirect; clients may behave unpredictably.", "Always send Location.")
        else:
            target = urljoin(url, location)
            if urlsplit(target).netloc != urlsplit(url).netloc:
                findings.add("Medium", "Redirect handling", path, f"Redirects off-site to {target}",
                             "Off-site redirects need review for open-redirect abuse.",
                             "Restrict redirect targets to an allow-list.")
            elif urlsplit(url).scheme == "https" and urlsplit(target).scheme == "http":
                findings.add("Medium", "Redirect handling", path, "Redirect downgrades HTTPS to HTTP",
                             "Downgrade exposes the next request to interception.", "Redirect to HTTPS only.")
            else:
                positives.append(f"{path}: {status} redirect stays same-origin (Location: {location})")

    # Error handling.
    if status >= 400:
        body = response.text[:2000].lower()
        markers = [m for m in VERBOSE_ERROR_MARKERS if m in body]
        if markers:
            findings.add("Medium", "Error handling", path, f"Verbose error content ({', '.join(markers)})",
                         "Stack traces or internal details aid attackers.", "Return generic error pages.")
        else:
            positives.append(f"{path}: {status} response has a minimal body (no stack trace)")

    if path == "/health" and status == 200:
        findings.add("Info", "Exposed endpoint", path,
                     f"Unauthenticated health endpoint returns '{response.text[:20]}'",
                     "Minimal content; acceptable for monitoring but confirm it never exposes internals.",
                     "Keep health output minimal or restrict it to monitoring hosts.")


def http_check(base_url: str, paths: list[str] | None = None) -> dict:
    base_url = validate_http_target(base_url)
    paths = paths or HTTP_PATHS
    findings, positives, observations = FindingSet(), [], []
    reachable = False

    with requests.Session() as session:
        session.headers["User-Agent"] = USER_AGENT
        for path in paths:
            url = urljoin(base_url, path.lstrip("/"))
            record = {"endpoint": path, "method": "GET", "url": url}
            try:
                # allow_redirects=False so the redirect itself can be inspected.
                response = session.get(url, timeout=HTTP_TIMEOUT, allow_redirects=False)
            except requests.exceptions.ConnectionError:
                record.update(status="CONNECTION_FAILED", error="Connection refused / host unreachable")
                observations.append(record)
                continue
            except requests.exceptions.Timeout:
                record.update(status="TIMEOUT", error=f"No response within {HTTP_TIMEOUT}s")
                observations.append(record)
                continue
            except requests.RequestException as exc:
                record.update(status="REQUEST_ERROR", error=type(exc).__name__)
                observations.append(record)
                continue
            reachable = True
            record.update(
                status=response.status_code, reason=response.reason,
                length=len(response.content),
                content_type=response.headers.get("Content-Type", "-"),
                server=response.headers.get("Server", "-"),
                location=response.headers.get("Location", "-"),
                set_cookie=" | ".join(_set_cookie_values(response)) or "-",
                elapsed_ms=round(response.elapsed.total_seconds() * 1000, 1),
            )
            observations.append(record)
            _analyze_response(url, path, response, findings, positives)

    if reachable and urlsplit(base_url).scheme == "http":
        findings.add("Medium", "Transport security", "/", "Service uses plaintext HTTP (no TLS)",
                     "Requests, responses and the session cookie travel unencrypted and can be read or "
                     "modified on the network. HSTS cannot be evaluated on an HTTP-only endpoint.",
                     "Serve over HTTPS (TLS 1.2+) and then add Strict-Transport-Security.")
    if not reachable:
        findings.add("Info", "Connectivity", "/", f"Target {base_url} unreachable",
                     "No HTTP response was received, so NO security conclusion can be drawn.",
                     "Start test_website.py and re-run the check.", status="Inconclusive")

    return {"target": base_url, "reachable": reachable, "time": datetime.now().isoformat(timespec="seconds"),
            "observations": observations, "findings": findings.as_list(), "positive_observations": positives}


def print_http_report(report: dict) -> None:
    banner(f"HTTP configuration check: {report['target']}")
    print(f"{'ENDPOINT':<11}{'STATUS':<19}{'LENGTH':<8}{'CONTENT-TYPE':<27}LOCATION")
    for obs in report["observations"]:
        if isinstance(obs["status"], int):
            print(f"{obs['endpoint']:<11}{str(obs['status']) + ' ' + obs['reason']:<19}"
                  f"{obs['length']:<8}{obs['content_type'][:25]:<27}{obs['location']}")
        else:
            print(f"{obs['endpoint']:<11}{obs['status']:<19}{obs.get('error', '')}")
    first = next((o for o in report["observations"] if isinstance(o["status"], int)), None)
    if first:
        print(f"\nServer header: {first['server']}   Set-Cookie on '/': "
              f"{next((o['set_cookie'] for o in report['observations'] if o['endpoint'] == '/'), '-')}")

    print(f"\nFindings ({len(report['findings'])}):")
    for f in report["findings"]:
        print(f"  [{f['id']}] {f['severity']:<6} {f['category']}: {f['observation']}")
        print(f"           endpoints: {', '.join(f['endpoints'])}")
        print(f"           why: {f['why_it_matters']}")
        print(f"           fix: {f['recommendation']}")
    if report["positive_observations"]:
        print("\nPositive / neutral observations:")
        for p in report["positive_observations"]:
            print(f"  - {p}")
    print("\nNOTE: Missing headers and banners are configuration BASELINE GAPS that merit review.")
    print("      They do not prove that any vulnerability is exploitable. Absence of findings")
    print("      would likewise not prove the site is secure.")


# PCAP result rendering (analysis itself runs on the server)
def print_pcap_report(data: dict) -> None:
    s = data.get("summary", {})
    banner(f"Server-side PCAP analysis: {s.get('file')}")
    print(f"SHA-256      : {s.get('sha256')}")
    print(f"Packets      : {s.get('packet_count')}  ({s.get('size_bytes')} bytes)")
    print(f"Capture span : {s.get('capture_start_utc')} -> {s.get('capture_end_utc')} "
          f"({s.get('duration_s')} s)")
    print(f"Protocols    : {', '.join(f'{k}={v}' for k, v in s.get('protocols', {}).items())}")
    hs = s.get("tcp_handshake", {})
    print(f"TCP handshake: SYN={hs.get('syn')} SYN-ACK={hs.get('syn_ack')} "
          f"completed={hs.get('completed_handshakes')} unanswered SYN={hs.get('unanswered_syn')}")
    print(f"TCP flags    : {s.get('tcp_flags')}")
    dns = s.get("dns", {})
    print(f"DNS (UDP/53) : well-formed={dns.get('well_formed')} malformed={dns.get('malformed_on_port_53')}")
    print("Top sources  : " + ", ".join(f"{ip} ({n})" for ip, n in s.get("top_sources", [])))
    print("Top services : " + ", ".join(f"{svc} ({n})" for svc, n in s.get("top_services", [])))
    print("Conversations:")
    for conv, n in s.get("top_conversations", []):
        print(f"   {conv:<42} {n} pkt")
    peaks = s.get("peak_packets_per_source", {})
    print(f"Peak packets per source in {peaks.get('window_s')}s: "
          + ", ".join(f"{ip}={n}" for ip, n in peaks.get("values", {}).items()))

    findings = data.get("findings", [])
    print(f"\nSuspicious-pattern detections ({len(findings)}):")
    for f in findings:
        print(f"  [{f.get('id')}] {f.get('severity'):<6} {f.get('category')}")
        print(f"           {f.get('source')} -> {f.get('target')}")
        ev = f.get("evidence", {})
        print("           evidence: " + "; ".join(f"{k}={v}" for k, v in ev.items()))
        print(f"           rationale: {f.get('rationale')}")
        print(f"           caveat: {f.get('caveat')}")
    print(f"\nNOTE: {data.get('disclaimer', '')}")


def print_response(resp: dict) -> None:
    status, code, message = resp.get("status"), resp.get("code"), resp.get("message")
    print(f"{status} {code}: {message}")
    if status == "ERROR" and code in ("AUTH_REQUIRED", "FORBIDDEN"):
        print("    (request rejected by the server's authorization check)")



# From Labs 1 and 3
#   Command Loop: Inherits the interactive loop and clean EXIT command from Lab 1 client.py.
#   Hidden Credentials: Uses getpass.getpass() from Lab 3 auth_client.py to ensure passwords and OTP tokens are never echoed to the screen.
#   Two-Step Challenge Sequence: Implements LOGIN -> OTP challenge workflow from Lab 3 auth_client.py.
# Other added features not in labs 0-5:
#   Session State Awareness: Tracks authenticated username, active role, and
#   session expiration time directly in the client instance.
#   Resilient Reconnection: If server disconnects, local tools (port scan,
#   HTTP check) remain fully usable, and option 1 re-establishes the TCP link.
#   Unified Forensic Exporters: Automated export of findings to reports/ in both CSV and JSON formats.

class AnalystConsole:
    def __init__(self, server_host: str, server_port: int, http_target: str, scan_start: int, scan_end: int):
        self.conn = Connection(server_host, server_port)
        self.http_target = http_target
        self.scan_start, self.scan_end = scan_start, scan_end
        self.user: str | None = None
        self.role: str | None = None

    # connection management
    def connect(self) -> None:
        try:
            welcome = self.conn.connect()
            self.user = self.role = None
            print_response(welcome)
            print(f"    Connected to {self.conn.host}:{self.conn.port} "
                  f"(framing: {welcome.get('data', {}).get('framing')}, "
                  f"encrypted: {welcome.get('data', {}).get('transport_encrypted')})")
        except ConnectionRefusedError:
            print(f"Connection refused by {self.conn.host}:{self.conn.port} - is server.py running?")
        except socket.timeout:
            print(f"Connection to {self.conn.host}:{self.conn.port} timed out.")
        except (ServerDisconnected, OSError) as exc:
            print(f"Could not connect: {exc}")

    def _lost(self, exc: Exception) -> None:
        self.user = self.role = None
        print(f"Server connection lost: {exc}")
        print("    Local tools (port scan, HTTP check) still work. Use option 1 to reconnect.")

    def call(self, cmd: str, args: dict | None = None) -> dict | None:
        if not self.conn.connected:
            print("Not connected to the server. Use option 1 to connect.")
            return None
        try:
            resp = self.conn.request(cmd, args)
        except ServerDisconnected as exc:
            self._lost(exc)
            return None
        if resp.get("status") == "BYE" or not self.conn.connected:
            print_response(resp)
            self.user = self.role = None
            print("    The server closed this session.")
            return None
        if resp.get("code") == "AUTH_REQUIRED":
            self.user = self.role = None  # e.g. session expired server-side
        return resp

    # menu actions
    def login(self) -> None:
        if not self.conn.connected:
            print("Not connected. Use option 1 first.")
            return
        username = prompt("Username")
        if not USERNAME_RE.fullmatch(username):
            print("Username must be 1-32 characters: letters, digits, '_', '.', '-'.")
            return
        password = read_secret("Password: ")
        if not password:
            print("Password cannot be empty.")
            return
        resp = self.call("LOGIN", {"username": username, "password": password})
        del password  # This is to not keep the plaintext in memory longer than needed
        if resp is None:
            return
        print_response(resp)
        if resp.get("code") != "OTP_REQUIRED":
            remaining = resp.get("data", {}).get("attempts_remaining")
            if remaining is not None:
                print(f"    Attempts remaining on this connection: {remaining}")
            return

        for _ in range(3):  # Local format check avoids server-side attempts on typos
            otp = read_secret("6-digit TOTP code: ").strip()
            if OTP_RE.fullmatch(otp):
                break
            print("The code must be exactly 6 digits.")
        else:
            print("No valid code entered. Run login again.")
            return
        resp = self.call("OTP", {"otp": otp})
        if resp is None:
            return
        print_response(resp)
        if resp.get("code") == "AUTHENTICATED":
            data = resp.get("data", {})
            self.user, self.role = data.get("user"), data.get("role")
            print(f"    Role: {self.role}   Permissions: {', '.join(data.get('permissions', []))}")
        elif "attempts_remaining" in resp.get("data", {}):
            print(f"    Attempts remaining on this connection: {resp['data']['attempts_remaining']}")

    def port_scan_menu(self) -> None:
        target = prompt("Target host", "127.0.0.1")
        start = prompt_int("Start port", self.scan_start, 1, 65535)
        end = prompt_int("End port", self.scan_end, 1, 65535)
        engine = "socket"
        if find_nmap():
            if prompt("Engine: 1) socket connect scan  2) python-nmap (-sT)", "1") == "2":
                engine = "nmap"
        try:
            print(f"Scanning {target} TCP {start}-{end} with the {engine} engine ...")
            report = port_scan(target, start, end, engine)
        except ScopeError as exc:
            print(f"Scope violation: {exc}")
            return
        except ValueError as exc:
            print(f"Invalid input: {exc}")
            return
        except Exception as exc:  # for nmap errors
            print(f"Scan failed: {type(exc).__name__}: {exc}")
            return
        print_scan_report(report, self.conn.port)
        path = save_csv(f"port_scan_{timestamp()}.csv", report["results"], ["port", "state", "service"])
        if path:
            print(f"Results saved to {path}")

    def http_check_menu(self) -> None:
        target = prompt("Target URL", self.http_target)
        try:
            print(f"Checking {target} paths {', '.join(HTTP_PATHS)} ...")
            report = http_check(target)
        except ScopeError as exc:
            print(f"Scope violation: {exc}")
            return
        print_http_report(report)
        stamp = timestamp()
        p1 = save_csv(f"http_observations_{stamp}.csv", report["observations"],
                      ["endpoint", "method", "status", "reason", "length", "content_type",
                       "server", "location", "set_cookie", "elapsed_ms", "error"])
        p2 = save_csv(f"http_findings_{stamp}.csv", report["findings"],
                      ["id", "severity", "category", "endpoints", "observation",
                       "why_it_matters", "recommendation", "status"])
        if p1 and p2:
            print(f"Saved {p1.name} and {p2.name} in {REPORT_DIR}")

    def pcap_menu(self) -> None:
        name = prompt("PCAP file on server", DEFAULT_PCAP)
        print("Requesting server-side analysis ...")
        resp = self.call("PCAP_ANALYZE", {"file": name})
        if resp is None:
            return
        if resp.get("status") != "OK":
            print_response(resp)
            return
        print_pcap_report(resp.get("data", {}))
        path = save_json(f"pcap_analysis_{timestamp()}.json", resp.get("data", {}))
        if path:
            print(f"Full JSON result saved to {path}")

    def diag(self) -> None:
        resp = self.call("DIAG")
        if resp is None:
            return
        print_response(resp)
        if resp.get("status") == "OK":
            print(json.dumps(resp.get("data", {}), indent=2))

    def whoami(self) -> None:
        resp = self.call("WHOAMI")
        if resp is None:
            return
        print_response(resp)
        if resp.get("status") == "OK":
            for key, value in resp.get("data", {}).items():
                print(f"    {key:<22}{value}")

    def logout(self) -> None:
        resp = self.call("LOGOUT")
        if resp is None:
            return
        print_response(resp)
        if resp.get("status") == "OK":
            self.user = self.role = None

    def raw(self) -> None:
        print("Protocol test mode: the line is sent EXACTLY as typed (no JSON wrapping).")
        print('Example: {"v":1,"cmd":"PCAP_ANALYZE","args":{}}   or   not-json')
        line = input("raw> ")
        if not self.conn.connected:
            print("Not connected to the server.")
            return
        try:
            resp = self.conn.send_raw(line)
        except ServerDisconnected as exc:
            self._lost(exc)
            return
        print(json.dumps(resp, indent=2))
        if not self.conn.connected:
            self.user = self.role = None
            print("    The server closed this session.")

    def help(self) -> None:
        resp = self.call("HELP")
        if resp is None:
            return
        for c in resp.get("data", {}).get("commands", []):
            print(f"  {c['cmd']:<13} {c['access']:<22} {c['description']}")

    # main loop
    def status_line(self) -> str:
        conn = f"{self.conn.host}:{self.conn.port} " + ("CONNECTED" if self.conn.connected else "DISCONNECTED")
        auth = f"{self.user} ({self.role})" if self.user else "not authenticated"
        return f"Server: {conn} | Auth: {auth}"

    def run(self) -> None:
        banner("Console")
        print("This is localhost only and plain TCP transport is not encrypted.")
        self.connect()
        actions = {
            "1": self.connect, "2": self.login, "3": self.port_scan_menu, "4": self.http_check_menu,
            "5": self.pcap_menu, "6": self.diag, "7": self.whoami, "8": self.logout,
            "9": self.raw, "?": self.help, "h": self.help, "help": self.help,
        }
        while True:
            print(self.status_line())
            print(" 1) Connect / reconnect to server      6) Server diagnostics   [admin]")
            print(" 2) Log in (password + TOTP MFA)       7) Who am I             [protected]")
            print(" 3) Local TCP port scan                8) Log out")
            print(" 4) Local HTTP security check          9) Send raw request (protocol test)")
            print(" 5) PCAP analysis on server [protected] ?) Help")
            print(" 0) Exit")
            try:
                choice = input("Select> ").strip().lower()
            except EOFError:
                choice = "0"
            if choice == "0":
                break
            action = actions.get(choice)
            if action is None:
                print("Invalid.")
                continue
            try:
                action()
            except EOFError:
                break
        if self.conn.connected:
            try:
                resp = self.conn.request("EXIT")
                print_response(resp)
            except ServerDisconnected:
                pass
        self.conn.close()
        print("Disconnected.")


def loopback_host(value: str) -> str:
    try:
        resolve_authorized_host(value)
    except ScopeError as exc:
        raise argparse.ArgumentTypeError(str(exc))
    return value


def main() -> int:
    parser = argparse.ArgumentParser(description="Analyst client")
    parser.add_argument("--host", default=DEFAULT_SERVER_HOST, type=loopback_host,
                        help="Sentinel server host (loopback only)")
    parser.add_argument("--port", default=DEFAULT_SERVER_PORT, type=int, help="Sentinel server port")
    parser.add_argument("--http-target", default=DEFAULT_HTTP_TARGET, help="HTTP checker base URL")
    parser.add_argument("--scan-range", default=f"{DEFAULT_SCAN_START}-{DEFAULT_SCAN_END}",
                        help="default port range for the scanner, e.g. 8760-8890")
    args = parser.parse_args()

    if not 1 <= args.port <= 65535:
        parser.error("port must be between 1 and 65535")
    match = re.fullmatch(r"(\d{1,5})-(\d{1,5})", args.scan_range)
    if not match:
        parser.error("--scan-range must look like START-END")
    start, end = int(match.group(1)), int(match.group(2))
    if not (1 <= start <= end <= 65535) or end - start + 1 > MAX_SCAN_PORTS:
        parser.error(f"--scan-range must be within 1-65535, START<=END, at most {MAX_SCAN_PORTS} ports")
    try:
        validate_http_target(args.http_target)
    except ScopeError as exc:
        parser.error(f"--http-target: {exc}")

    console = AnalystConsole(args.host, args.port, args.http_target, start, end)
    try:
        console.run()
    except KeyboardInterrupt:
        print("\nInterrupted - closing connection.")
        console.conn.close(send_exit=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())

