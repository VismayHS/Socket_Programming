# Submission Checklist - Socket Programming Mini Project

## Core files present

- [x] main.py (threaded scanner orchestration)
- [x] banner_grabber.py (HTTP/FTP/FTPS banner grabbing via TCP sockets)
- [x] ssl_scanner.py (HTTPS banner grabbing via TLS)
- [x] service_identifier.py (service/version fingerprinting logic)
- [x] servers.txt (multi-server input list)
- [x] results.txt (generated scan report)
- [x] README.md (project documentation)
- [x] ground_truth.csv (strict accuracy evaluation input)

## Rubric mapping

- Problem definition and architecture: README.md
- Core implementation (socket creation/connect/send/recv): banner_grabber.py, ssl_scanner.py
- Feature implementation (HTTP/FTP grabbing, service identification, multithreading, SSL/TLS): all Python modules
- Performance evaluation (latency, throughput, identification success): results.txt summary section
- Accuracy evaluation (strict match against labels): results.txt strict accuracy section using ground_truth.csv

## Demo checklist

- [ ] Run: python main.py
- [ ] Show thread-based concurrent scans in terminal output
- [ ] Show HTTP/HTTPS/FTP/FTPS fields in results.txt
- [ ] Show performance summary in results.txt
- [ ] Show strict accuracy line in results.txt
