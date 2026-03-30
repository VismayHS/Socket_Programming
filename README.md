# Web Server Fingerprinting Tool

## 1. Project Overview

This project is a low-level socket programming implementation in Python for identifying server software by collecting and analyzing service banners from multiple protocols.

It scans each target host using the following protocols:

- HTTP over TCP on port 80.
- HTTPS over TLS on port 443.
- FTP over TCP on port 21.
- FTPS using explicit TLS upgrade on FTP control channel with AUTH TLS.

It then identifies likely server products and versions, measures performance, and writes a full report.

## 2. Requirement Coverage (Rubric Mapping)

- Direct TCP or UDP socket usage: implemented using Python socket APIs directly without high-level HTTP clients.
- SSL or TLS secure communication: HTTPS scanning via TLS handshake and FTPS probe via AUTH TLS.
- Multiple concurrent clients: one thread per host for concurrent scanning.
- Network socket communication only: all probing done by socket connections to remote hosts.
- Performance evaluation: reports latency, throughput, and identification success rate.
- Accuracy evaluation: strict labeled evaluation supported via ground_truth.csv.

Relevant files for these requirements:

- main.py
- banner_grabber.py
- ssl_scanner.py
- service_identifier.py

## 3. Implemented Features

- HTTP banner grabbing.
- HTTPS banner grabbing with TLS.
- FTP greeting banner grabbing.
- FTPS negotiation attempt and TLS cipher capture.
- Service identification and version extraction.
- Concurrent multi-host scanning.
- Robust error handling for DNS, timeout, and SSL errors.
- Report generation in results.txt.
- Performance summary metrics.
- Strict accuracy computation against labeled ground truth.

## 4. How It Works (Step-by-Step)

1. Target loading: hosts are read from servers.txt.
1. Concurrent scanning: main.py starts one thread per host.
1. Per-host protocol probes: HTTP over raw TCP, HTTPS after TLS handshake, FTP greeting read, and FTPS attempted with AUTH TLS.
1. Fingerprinting: service_identifier.py parses banners and headers such as Server and applies known signatures with regex version matching.
1. Result aggregation: thread-safe append to shared results list and primary service guess selection.
1. Evaluation and report: performance summary computed, optional strict accuracy computed if ground_truth.csv exists, and final report saved to results.txt.

## 5. Architecture

Text flow:

servers.txt -> main.py (thread per host) -> banner_grabber.py and ssl_scanner.py (network probes) -> service_identifier.py (fingerprinting) -> results.txt (host-level results plus performance plus accuracy)

## 6. Project Structure

.

- main.py
- banner_grabber.py
- ssl_scanner.py
- service_identifier.py
- servers.txt
- ground_truth.csv
- results.txt
- SUBMISSION_CHECKLIST.md
- README.md

## 7. How to Run

Prerequisites:

- Python 3.8 or newer.
- Internet connectivity.

Run steps:

1. Add targets in servers.txt with one hostname per line.
1. Optionally update ground_truth.csv with strict accuracy labels.
1. Run the scanner using python main.py.

Outputs:

- Live terminal scan progress.
- Full report in results.txt.

## 8. Input Files

servers.txt format example:

nginx.org
apache.org
httpbin.org

ground_truth.csv format example:

host,expected_service
nginx.org,nginx
apache.org,Varnish

## 9. Output File (results.txt)

Per host, the report includes:

- HTTP Service.
- HTTPS Service.
- FTP Service.
- FTPS Service.
- Primary Guess.
- Response Time.

Summary section includes:

- Total Hosts Scanned.
- Total Scan Duration.
- Average Per-Host Latency.
- Throughput in hosts per second.
- Identification Success Rate.
- Strict Accuracy when labels are available.

## 10. Viva and Demo Section

### A. Recommended Demo Flow (5 to 8 minutes)

1. Problem statement in 30 to 45 seconds: explain banner-based server fingerprinting using low-level sockets.
1. Architecture in 1 minute: show file responsibilities and scan pipeline.
1. Code walkthrough in 2 to 3 minutes: main.py for threading and metrics, banner_grabber.py for HTTP and FTP and FTPS sockets, ssl_scanner.py for HTTPS TLS handshake, and service_identifier.py for banner parsing.
1. Live execution in 1 to 2 minutes: run python main.py and show concurrent scan logs plus summary.
1. Results interpretation in 1 minute: open results.txt and explain performance and strict accuracy lines.

### B. Viva Questions You Are Likely to Get

1. Why TCP and not UDP: HTTP and HTTPS and FTP are connection-oriented and rely on reliable ordered delivery.
1. Where secure communication is implemented: HTTPS uses TLS-wrapped sockets and FTPS uses AUTH TLS on FTP control channel.
1. How concurrency is implemented: one thread per host and a lock-protected shared results list.
1. How correctness is evaluated: strict accuracy compares detected signatures against labels in ground_truth.csv.
1. What limitations exist: banner masking, network filtering, and latency can reduce visible identity data.

### C. Demo Tips for Better Evaluation

- Keep 5 to 8 stable hosts in servers.txt for reproducible output.
- Keep matching labels in ground_truth.csv for visible strict accuracy scoring.
- Run once before viva to avoid DNS surprises during demonstration.
- Explicitly connect output metrics to rubric terms such as latency, throughput, scalability, and secure communication.

## 11. Limitations

- Banner masking or reverse proxies can hide true backend identity.
- Firewall rules and rate limiting can cause timeouts.
- Accuracy depends on publicly exposed service metadata.

## 12. Future Improvements

- Add UDP-based probing where relevant.
- Add retry and backoff policy for unstable links.
- Add richer fingerprint database and confidence scoring.
- Add CSV and JSON export for analytics.

## 13. Author

Amar Nawadagi

CSE (AI/ML)
