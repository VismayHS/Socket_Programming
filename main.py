# Import csv so we can optionally read ground-truth labels for accuracy validation.
import csv
# Import threading to run multiple host scans concurrently like parallel client probes.
import threading
# Import time to measure per-host latency and overall throughput of the scanner.
import time
# Import plain HTTP and FTP banner grabbers that operate over raw TCP sockets.
from banner_grabber import grab_ftp_banner, grab_ftps_banner, grab_http_banner
# Import service fingerprint parser that maps banners to server products and versions.
from service_identifier import identify_service
# Import HTTPS banner grabber that performs TLS handshake before HTTP exchange.
from ssl_scanner import grab_https_banner

# Keep scan records in memory so we can write one consolidated report after all threads finish.
results = []
# Protect shared list access because multiple scanner threads append at the same time.
results_lock = threading.Lock()


# Decide a single representative service per host for quick summary and accuracy checks.
def pick_primary_service(http_service, https_service, ftp_service, ftps_service):
    # Prefer HTTPS identity first because encrypted web endpoints are most common in modern deployments.
    if https_service not in ("Unavailable", "Unknown"):
        return https_service
    # Fall back to HTTP identity if HTTPS is blocked but cleartext web service responds.
    if http_service not in ("Unavailable", "Unknown"):
        return http_service
    # Use FTPS identity when web ports are closed but secure FTP control channel is available.
    if ftps_service not in ("Unavailable", "Unknown"):
        return ftps_service
    # Use plain FTP identity only when no stronger protocol fingerprint is available.
    if ftp_service not in ("Unavailable", "Unknown"):
        return ftp_service
    # Return Unknown when no protocol provides a recognizable service signature.
    return "Unknown"


# Read server targets from file so the scanner can test multiple hosts in one run.
def load_servers(file_path="servers.txt"):
    # Wrap file access in try/except so missing input file is reported clearly.
    try:
        # Open the target list in read mode with UTF-8 decoding for portability.
        with open(file_path, "r", encoding="utf-8") as file_handle:
            # Strip whitespace and ignore blank rows so each line maps to one network endpoint.
            raw_hosts = [line.strip() for line in file_handle if line.strip()]
    # Handle missing file gracefully with an actionable error message.
    except FileNotFoundError:
        print(f"[error] {file_path} not found. Create the file and add at least one host.")
        return []
    # Handle unexpected read/decode issues without crashing the scanner.
    except Exception as error:
        print(f"[error] could not read {file_path}: {error}")
        return []
    # Deduplicate while preserving order so duplicate host entries do not spawn duplicate threads.
    return list(dict.fromkeys(raw_hosts))


# Read optional host-to-expected-service mappings for strict fingerprint accuracy scoring.
def load_ground_truth(file_path="ground_truth.csv"):
    # Start with an empty mapping so missing files do not crash normal scanning workflow.
    expected_mapping = {}
    # Wrap file operations in try/except because this file is optional for submissions.
    try:
        # Open CSV in universal newline mode for consistent parsing across operating systems.
        with open(file_path, "r", encoding="utf-8", newline="") as csv_file:
            # Parse rows by header names like host and expected_service.
            reader = csv.DictReader(csv_file)
            # Walk each expected row and normalize host keys for case-insensitive lookups.
            for row in reader:
                # Extract and normalize host value from CSV row.
                host = row.get("host", "").strip().lower()
                # Extract expected product signature used for correctness comparison.
                expected_service = row.get("expected_service", "").strip()
                # Store only valid entries so malformed rows do not pollute accuracy metrics.
                if host and expected_service:
                    expected_mapping[host] = expected_service
    # Ignore missing file because strict accuracy check is optional and not required to run scanner.
    except FileNotFoundError:
        pass
    # Surface parsing errors to user without stopping the main network scan pipeline.
    except Exception as error:
        print(f"[warning] ground_truth.csv could not be parsed: {error}")
    # Return collected expected labels for use in post-scan evaluation.
    return expected_mapping


# Compare predicted fingerprints with expected labels when a ground-truth file is provided.
def evaluate_strict_accuracy(scan_results, expected_mapping):
    # Return neutral status when no ground-truth labels are available for objective comparison.
    if not expected_mapping:
        return "Strict Accuracy: Not evaluated (ground_truth.csv not provided)."
    # Track how many labeled hosts were correctly identified.
    correct_matches = 0
    # Track how many labeled hosts were actually evaluated.
    evaluated_hosts = 0
    # Iterate all scan outputs and test only hosts that exist in the expected label map.
    for item in scan_results:
        # Normalize host for case-insensitive dictionary lookup.
        host = item["host"].lower()
        # Skip hosts with no expected label to avoid inflating denominator.
        if host not in expected_mapping:
            continue
        # Increase denominator for each labeled host we compare.
        evaluated_hosts += 1
        # Read expected signature for this host.
        expected_value = expected_mapping[host].lower()
        # Merge all identified protocol fingerprints into one searchable lowercase string.
        observed_values = " | ".join(
            [
                item["http_service"],  # Include HTTP fingerprint from TCP port 80 probe.
                item["https_service"],  # Include HTTPS fingerprint from TLS-wrapped port 443 probe.
                item["ftp_service"],  # Include FTP control-channel greeting fingerprint from port 21.
                item["ftps_service"],  # Include FTPS fingerprint from AUTH TLS upgrade attempt.
                item["primary_service"],  # Include final selected identity used in summary reporting.
            ]
        ).lower()
        # Count as correct if expected signature appears in any observed protocol fingerprint.
        if expected_value in observed_values:
            correct_matches += 1
    # Handle edge case where labels exist but none of scanned hosts match those labels.
    if evaluated_hosts == 0:
        return "Strict Accuracy: Not evaluated (no overlap between servers.txt and ground_truth.csv)."
    # Convert ratio to percentage with two decimal places for report readability.
    accuracy_percent = round((correct_matches / evaluated_hosts) * 100, 2)
    # Return formatted strict-accuracy statement for console and report file.
    return (
        f"Strict Accuracy: {accuracy_percent}% "
        f"({correct_matches}/{evaluated_hosts} labeled hosts matched)."
    )


# Build aggregate performance metrics required by networking project evaluation criteria.
def build_performance_summary(scan_results, total_duration):
    # Count scanned hosts to compute throughput and identification rates.
    host_count = len(scan_results)
    # Avoid division by zero if target list is empty.
    if host_count == 0:
        return "No hosts were scanned."
    # Calculate sum of per-host scan latency measurements.
    total_host_latency = sum(item["response_time"] for item in scan_results)
    # Compute average host latency as a simple performance metric.
    average_latency = round(total_host_latency / host_count, 2)
    # Compute scan throughput as hosts processed per second across all worker threads.
    throughput = round(host_count / total_duration, 2) if total_duration > 0 else 0.0
    # Count hosts where at least one protocol produced a usable fingerprint.
    identified_hosts = sum(
        1 for item in scan_results if item["primary_service"] not in ("Unavailable", "Unknown")
    )
    # Compute identification success ratio as practical proxy for fingerprinting effectiveness.
    identification_rate = round((identified_hosts / host_count) * 100, 2)
    # Return one compact text block so caller can print and persist the same summary.
    return (
        f"Performance Summary\n"
        f"Total Hosts Scanned: {host_count}\n"
        f"Total Scan Duration: {round(total_duration, 2)} sec\n"
        f"Average Per-Host Latency: {average_latency} sec\n"
        f"Throughput: {throughput} hosts/sec\n"
        f"Identification Success Rate: {identification_rate}% ({identified_hosts}/{host_count})"
    )


# Scan one host over multiple TCP application protocols and store normalized fingerprint results.
def scan_host(host):
    # Print progress marker so user can follow concurrent network probing in real time.
    print(f"[scan] {host}")
    # Capture start timestamp for host-level latency measurement.
    start_time = time.time()
    # Grab HTTP banner via plain TCP port 80 connection.
    http_banner = grab_http_banner(host)
    # Grab HTTPS banner via TLS-encrypted TCP port 443 connection.
    https_banner = grab_https_banner(host)
    # Grab FTP greeting banner via plain TCP control channel on port 21.
    ftp_banner = grab_ftp_banner(host)
    # Attempt explicit FTPS upgrade (AUTH TLS) for secure FTP control-channel probing.
    ftps_banner = grab_ftps_banner(host)
    # Convert HTTP banner text to product/version fingerprint.
    http_service = identify_service(http_banner)
    # Convert HTTPS banner text to product/version fingerprint.
    https_service = identify_service(https_banner)
    # Convert FTP banner text to product/version fingerprint.
    ftp_service = identify_service(ftp_banner)
    # Convert FTPS banner text to product/version fingerprint.
    ftps_service = identify_service(ftps_banner)
    # Pick one representative identity for concise reporting and strict-accuracy checks.
    primary_service = pick_primary_service(http_service, https_service, ftp_service, ftps_service)
    # Capture end timestamp after all protocol probes complete.
    end_time = time.time()
    # Compute host scan duration and round for readable output.
    response_time = round(end_time - start_time, 2)
    # Build structured result record for this host.
    host_result = {
        "host": host,  # Store target hostname for report traceability.
        "http_service": http_service,  # Store HTTP-layer fingerprint result.
        "https_service": https_service,  # Store HTTPS/TLS-layer fingerprint result.
        "ftp_service": ftp_service,  # Store plain FTP control-channel fingerprint result.
        "ftps_service": ftps_service,  # Store FTPS (TLS-upgraded FTP) fingerprint result.
        "primary_service": primary_service,  # Store best single service guess across protocols.
        "response_time": response_time,  # Store per-host latency used in performance evaluation.
    }
    # Lock shared state before appending because multiple threads write simultaneously.
    with results_lock:
        # Append this host result so final reporting can happen after all joins.
        results.append(host_result)
    # Print compact per-host summary so operator can monitor scanner behavior while running.
    print(
        f"[done] {host} | HTTP: {http_service} | HTTPS: {https_service} | "
        f"FTP: {ftp_service} | FTPS: {ftps_service} | Time: {response_time}s"
    )


# Persist full scan results plus evaluation summaries in a submission-friendly text report.
def write_results_file(file_path, scan_results, performance_summary, strict_accuracy_summary):
    # Open report file in write mode to replace old scan data with latest execution.
    with open(file_path, "w", encoding="utf-8") as file_handle:
        # Write section heading for per-host fingerprint results.
        file_handle.write("Web Server Fingerprinting Results\n")
        # Write separator line to improve readability.
        file_handle.write("=" * 60 + "\n\n")
        # Iterate host results in deterministic order for cleaner review.
        for item in scan_results:
            # Write host label for this result block.
            file_handle.write(f"Host: {item['host']}\n")
            # Write identified HTTP service fingerprint.
            file_handle.write(f"HTTP Service : {item['http_service']}\n")
            # Write identified HTTPS service fingerprint.
            file_handle.write(f"HTTPS Service: {item['https_service']}\n")
            # Write identified FTP service fingerprint.
            file_handle.write(f"FTP Service  : {item['ftp_service']}\n")
            # Write identified FTPS service fingerprint.
            file_handle.write(f"FTPS Service : {item['ftps_service']}\n")
            # Write chosen primary identity.
            file_handle.write(f"Primary Guess: {item['primary_service']}\n")
            # Write per-host latency in seconds.
            file_handle.write(f"Response Time: {item['response_time']} sec\n")
            # Add separator between hosts.
            file_handle.write("-" * 60 + "\n")
        # Add spacing before summary section.
        file_handle.write("\n")
        # Write performance metrics section.
        file_handle.write(performance_summary + "\n")
        # Add spacing before strict accuracy status.
        file_handle.write("\n")
        # Write strict accuracy statement.
        file_handle.write(strict_accuracy_summary + "\n")


# Coordinate end-to-end workflow: load targets, scan concurrently, evaluate, and write report.
def main():
    # Load host targets from servers.txt for multi-host concurrent probing.
    servers = load_servers("servers.txt")
    # Stop early if no targets are provided to avoid empty thread creation.
    if not servers:
        print("No hosts found in servers.txt")
        return
    # Reset shared results before each run so repeated executions start from a clean state.
    with results_lock:
        results.clear()
    # Print startup banner for operator context.
    print("Starting Web Server Fingerprinting Tool")
    # Print thread count to show planned concurrency level.
    print(f"Threads used: {len(servers)}")
    # Capture global start time for whole-scan throughput measurement.
    global_start_time = time.time()
    # Prepare container for worker thread objects.
    threads = []
    # Create and start one scanner thread per target host.
    for server in servers:
        # Build thread for current host scan routine.
        thread = threading.Thread(target=scan_host, args=(server,))
        # Start thread to begin concurrent network probing.
        thread.start()
        # Track thread reference so we can join later.
        threads.append(thread)
    # Wait for all host scans to complete before generating final report.
    for thread in threads:
        # Block until this worker finishes its network operations.
        thread.join()
    # Compute full run duration for throughput metric.
    total_duration = time.time() - global_start_time
    # Sort results by host name so output order is stable across runs.
    ordered_results = sorted(results, key=lambda item: item["host"].lower())
    # Load optional expected labels for strict accuracy evaluation.
    expected_mapping = load_ground_truth("ground_truth.csv")
    # Build performance section required by project rubric.
    performance_summary = build_performance_summary(ordered_results, total_duration)
    # Build strict accuracy section from optional label file.
    strict_accuracy_summary = evaluate_strict_accuracy(ordered_results, expected_mapping)
    # Persist all details in results.txt for submission and demonstration.
    write_results_file("results.txt", ordered_results, performance_summary, strict_accuracy_summary)
    # Print final completion marker with report location.
    print("Scan completed. Results saved in results.txt")
    # Print performance summary so user sees runtime metrics immediately.
    print(performance_summary)
    # Print strict accuracy status so user knows whether label-based scoring ran.
    print(strict_accuracy_summary)


# Execute the scanner only when this file is run directly, not when imported as a module.
if __name__ == "__main__":
    # Launch the main orchestration function.
    main()