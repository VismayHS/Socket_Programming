# Web Server Fingerprinting Tool

Socket-programming mini project for identifying likely server software using low-level TCP/TLS banner collection.

## 1. Project Summary

This project fingerprints remote hosts by opening raw socket connections and collecting protocol banners from:

- HTTP (TCP 80)
- HTTPS (TLS over TCP 443)
- FTP (TCP 21)
- FTPS (explicit TLS upgrade using `AUTH TLS` on FTP control channel)

After scanning, it extracts probable service names/versions, computes performance metrics, optionally validates against labeled ground truth, and writes a detailed report to `results.txt`.

## 2. Key Features

- Low-level socket communication (no high-level HTTP client libraries)
- TCP-only transport for all probes (`socket.SOCK_STREAM`; no UDP probes)
- TLS-based HTTPS probing
- FTPS negotiation attempt with cipher reporting
- Multi-host concurrent scanning using threads
- Banner parsing and service/version identification
- Bounded connection deadlines per probe to avoid long hangs on multi-IP hosts
- Per-host latency tracking and run-level performance summary
- Optional strict accuracy evaluation with `ground_truth.csv`
- Submission-friendly text report generation

## 3. Technology and Networking Concepts

- Language: Python 3
- Core modules: `socket`, `ssl`, `threading`, `time`, `csv`, `re`

Networking concepts used:

- TCP client sockets
- TLS handshake and secure channel setup
- Application-layer protocol probing (HTTP/FTP)
- Concurrent client design (one thread per target host)

## 3A. TCP Requirement Compliance

This project follows the requirement to use TCP for socket communication:

- HTTP probe: TCP (`socket.SOCK_STREAM`) to port 80
- HTTPS probe: TCP to port 443, then TLS handshake
- FTP probe: TCP to port 21
- FTPS probe: TCP to port 21, then explicit TLS upgrade with `AUTH TLS`

No UDP-based probing is used.

## 4. Folder Structure

```text
CN-Project/
|- main.py
|- banner_grabber.py
|- ssl_scanner.py
|- service_identifier.py
|- servers.txt
|- ground_truth.csv
|- results.txt
|- SUBMISSION_CHECKLIST.md
`- README.md
```

## 5. File Responsibilities

- `main.py`: orchestration, threading, metrics, strict accuracy, result file writing
- `banner_grabber.py`: HTTP/FTP/FTPS raw socket probes
- `ssl_scanner.py`: HTTPS probe over TLS
- `service_identifier.py`: banner parsing and signature matching
- `servers.txt`: input host list (one hostname per line)
- `ground_truth.csv`: expected labels for strict accuracy checks
- `results.txt`: generated scan report

## 6. End-to-End Workflow

1. Load targets from `servers.txt`.
2. Start one worker thread per host.
3. For each host, run HTTP, HTTPS, FTP, and FTPS probes.
4. Parse banners and infer service identity.
5. Select a `Primary Guess` per host.
6. Compute performance metrics (latency, throughput, success rate).
7. Optionally compute strict accuracy from `ground_truth.csv`.
8. Save full output to `results.txt`.

## 7. Setup Instructions

### Prerequisites

- Python 3.8 or newer
- Internet connectivity

### Step-by-step setup

1. Open terminal in the project folder.
2. Verify Python installation:

```bash
python --version
```

3. (Optional but recommended) Create and activate a virtual environment:

```bash
python -m venv .venv
```

Windows PowerShell:

```powershell
.\.venv\Scripts\Activate.ps1
```

No third-party dependencies are required.

## 8. Input Configuration

### `servers.txt`

Add one hostname per line:

```text
nginx.org
apache.org
httpbin.org
test.rebex.net
```

### `ground_truth.csv` (optional)

Use this only if you want strict labeled evaluation:

```csv
host,expected_service
nginx.org,nginx
apache.org,Varnish
httpbin.org,gunicorn
```

## 9. Usage

Run the scanner:

```bash
python main.py
```

You will see:

- live `[scan]` and `[done]` logs for each host
- final performance summary in terminal
- strict accuracy status (if labels are available)

Main report output:

- `results.txt`

## 10. Output Details (`results.txt`)

For each host:

- HTTP Service
- HTTPS Service
- FTP Service
- FTPS Service
- Primary Guess
- Response Time

Summary block:

- Total Hosts Scanned
- Total Scan Duration
- Average Per-Host Latency
- Throughput (hosts/sec)
- Identification Success Rate
- Strict Accuracy

## 11. Rubric Mapping

- Direct socket communication: `banner_grabber.py`, `ssl_scanner.py`
- TCP usage proof: `_create_tcp_connection(...)` in `banner_grabber.py` and `ssl_scanner.py` uses `socket.SOCK_STREAM`
- Secure communication (TLS): `ssl_scanner.py`, FTPS logic in `banner_grabber.py`
- Concurrent clients: thread-per-host model in `main.py`
- Performance evaluation: summary generated in `main.py` and written to `results.txt`
- Accuracy evaluation: `ground_truth.csv` comparison in `main.py`

## 12. GitHub Upload Steps (For Submission)

Use these commands if your project is not yet pushed:

```bash
git init
git add .
git commit -m "Initial project submission: Web Server Fingerprinting Tool"
git branch -M main
git remote add origin https://github.com/<your-username>/<your-repo-name>.git
git push -u origin main
```

If the repo is already connected:

```bash
git add .
git commit -m "Update README and submission docs"
git push
```

After pushing, submit this link:

```text
https://github.com/<your-username>/<your-repo-name>
```

## 13. Demo / Viva Quick Plan

1. Explain objective: fingerprint servers with low-level sockets.
2. Show architecture and file roles.
3. Run `python main.py` live.
4. Open `results.txt` and explain host-wise fields.
5. Highlight performance and strict accuracy lines.

## 14. Limitations

- Hidden or spoofed banners can reduce identification quality.
- Firewalls, rate limits, or DNS failures can affect results.
- Banner-based fingerprinting cannot always reveal backend services behind proxies/CDNs.

## 15. Future Improvements

- Add richer signature database and confidence scores.
- Add retry/backoff for unstable targets.
- Export report in CSV/JSON format.
- Add optional port scanning phase before probing.

## 16. Author

Amar Nawadagi  
CSE (AI/ML)
