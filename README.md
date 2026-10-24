# FSCT 8561 - Midterm: Operation Sentinel
Billy Zandan, A01371854  
FSCT 8561 - Security Applications

---

## 1. Overview
The application integrates techniques from Labs 0 through 5 into a unified client-server security application:
- Port Scanner (From Lab 2): Scans localhost ports 8760-8890 using multi-threaded TCP sockets.
- HTTP Configuration Checker (from Lab 5): Audits security headers, cookies, and server banners on `http://127.0.0.1:8765/`.
- Authenticated TCP Server (From Labs 0, 1, 3): Listens on `127.0.0.1:8888` with PBKDF2 password hashing and TOTP MFA.
- Offline PCAP Analyzer (From Lab 4): Dissects `FSCT8561_Operation_Sentinel_Traffic.pcap` using Scapy to detect port scans, bursts, and anomalies.
- Audit Logging: Logs security events to `sentinel_audit.log` with strict redaction of passwords and OTP secrets.

---

## 2. Setup Instructions

### Prerequisites
- Python 3.10 or higher.
- Standard terminal (PowerShell, Command Prompt, or Bash).

### Install Dependencies
Install all required Python packages with a single command:
```bash
pip install -r requirements.txt
```
*(Dependencies: `pyotp`, `requests`, `scapy`, `python-nmap`)*

---

## 3. Pre-Configured Test Credentials

Pre-enrolled test accounts are stored in `users.json`. The following credentials allow immediate testing of authentication and role-based access control (RBAC):

| Username | Password | Role | Capabilities | Base32 TOTP Secret | Get Live 6-Digit OTP |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **`analyst`** | `Cyber123!` | `analyst` | Port Scan, HTTP Check, PCAP Analysis | `PVM2Y6LYSOYQPIIK46CAJFID44FFF4RF` | `python server.py --show-otp analyst` |
| **`admin`** | `AdminSecret2026!` | `admin` | All commands, including Server Diagnostics (`DIAG`) | `5KH3U5EQYLJ7OR24E4OS6V35GTCDXH4X` | `python server.py --show-otp admin` |

### Obtaining the 6-Digit TOTP Code
Run `python server.py --show-otp <username>` in a terminal to display the current 6-digit code.


### Enrolling New Accounts (Optional)
To enroll an additional test account, execute:
```python
python server.py --enroll <username> --role <analyst|admin>
```

---

## 4. Run Instructions

Requires three separate terminal windows:

### Terminal 1: Start HTTP Test Website
```python
python test_website.py
```
*Listens on `http://127.0.0.1:8765/` (intentionally misconfigured for baseline security review).*

### Terminal 2: Start Sentinel TCP Server
```python
python server.py
```
*Listens on `127.0.0.1:8888` (plain TCP transport with newline-delimited JSON framing).*

### Terminal 3: Start Interactive Client Console
```python
python client.py
```
*Launches the interactive console.*

---

## 5. Testing Instructions

Testing can be performed using the automated test tool or through manual execution.

### A. Automated Test Suite (Fastest & Complete)
Execute the automated test runner to validate all 14 end-to-end security test scenarios:
```bash
python run_tests.py
```
The test automatically initializes background test services, executes all 14 test cases, verifies assertions, and terminates services cleanly.

**Expected Automated Test Summary**:
- `TEST 1`: Successful 2FA login (Password + TOTP) -> **Pass**
- `TEST 2`: Failed password rejection -> **Pass**
- `TEST 3`: Failed TOTP code rejection -> **Pass**
- `TEST 4`: Unauthenticated command rejection (`AUTH_REQUIRED`) -> **Pass**
- `TEST 5`: RBAC role enforcement (`analyst` blocked from `DIAG`) -> **Pass**
- `TEST 6`: Open port detection (ports 8765 & 8888 detected open) -> **Pass**
- `TEST 7`: Closed port detection (port 8766 detected closed) -> **Pass**
- `TEST 8`: HTTP baseline security check (10 findings detected) -> **Pass**
- `TEST 9`: HTTP connection failure handling -> **Pass**
- `TEST 10`: Server PCAP threat detection (flags 6 anomalies) -> **Pass**
- `TEST 11`: Malformed frame and JSON input handling -> **Pass**
- `TEST 12`: TOTP replay protection across sessions -> **Pass**
- `TEST 13`: Clean socket disconnection (`EXIT` -> `BYE GOODBYE`) -> **Pass**
- `TEST 14`: Audit log credential redaction (zero passwords logged) -> **Pass**

Results are saved to `reports/test_execution_results.json`.

---

### B. Manual Execution Ste

Launch `python client.py` in the third terminal and execute menu options accordingly:

1. Option 1 (Connect): Connects socket to `127.0.0.1:8888`.
2. Option 5 before login (Test RBAC): Request PCAP analysis before authentication. The server returns `ERROR AUTH_REQUIRED`.
3. Option 2 (Log In):
   - Username: `analyst`
   - Password: `Cyber123!`
   - 6-digit OTP: Obtain code with `python server.py --show-otp analyst` in another terminal.
   - Server status updates to `analyst (analyst)`.
4. Option 6 (Role Check): Request server diagnostics as `analyst`. The server returns `ERROR FORBIDDEN` (admin required).
5. Option 3 (Port Scan): Scan `127.0.0.1:8760-8890`. Reports ports `8765` and `8888` open, and port `8760` closed.
6. Option 4 (HTTP Check): Inspect `http://127.0.0.1:8765/`. Reports 10 missing headers and cookie attributes.
7. Option 5 (PCAP Analysis): Run analysis on `FSCT8561_Operation_Sentinel_Traffic.pcap`. The server returns 123 packets and 6 detections.
8. Option 7 (Who Am I): Displays session username, role, and login timestamp.
9. Option 9 (Protocol Test): Send malformed input `not-json` to verify `BAD_JSON` handling.
10. Option 8 (Log Out): Resets session back to unauthenticated state.
11. Option 0 (Exit): Sends `EXIT`, receives `BYE GOODBYE`, and terminates socket connection cleanly.
