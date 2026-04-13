# Import socket for low-level TCP communication used by HTTP and FTP probing.
import socket
# Import ssl so FTP control channel can be upgraded to TLS for FTPS probing.
import ssl
# Import time to enforce total connection deadlines across multiple resolved IPs.
import time


# Create TCP connection with a hard total timeout even when host resolves to many IP addresses.
def _create_tcp_connection(host, port, timeout):
    # Compute absolute deadline so all address attempts share one total timeout budget.
    deadline = time.monotonic() + timeout
    # Keep last connection error to raise meaningful diagnostics if all attempts fail.
    last_error = socket.timeout("Connection timed out")
    # Resolve host to candidate IPv4/IPv6 socket endpoints.
    address_candidates = socket.getaddrinfo(
        host,
        port,
        family=socket.AF_UNSPEC,
        type=socket.SOCK_STREAM,
    )
    # Try candidates one by one until one succeeds or the timeout budget is exhausted.
    for family, socktype, proto, _, sockaddr in address_candidates:
        # Calculate remaining timeout budget before trying the next endpoint.
        remaining = deadline - time.monotonic()
        # Stop when no timeout budget remains.
        if remaining <= 0:
            break
        # Create socket for this specific endpoint family and protocol.
        tcp_socket = socket.socket(family, socktype, proto)
        # Attempt connect and close socket on failure to avoid resource leaks.
        try:
            # Apply remaining timeout budget to this attempt.
            tcp_socket.settimeout(remaining)
            # Connect to candidate endpoint.
            tcp_socket.connect(sockaddr)
            # Return connected socket to caller.
            return tcp_socket
        except Exception as error:
            # Keep latest failure for actionable final exception.
            last_error = error
            # Close failed socket attempt.
            tcp_socket.close()
    # Raise timeout when budget ended before any successful connection.
    if deadline - time.monotonic() <= 0:
        raise socket.timeout("Connection timed out")
    # Raise most relevant final error from connection attempts.
    raise last_error


# Receive only HTTP response headers so banner extraction is fast and memory-safe.
def _receive_http_headers(stream_socket, max_bytes=16384):
    # Start with an empty byte buffer for incremental socket reads.
    response = b""
    # Keep reading until headers end marker appears or maximum byte budget is reached.
    while b"\r\n\r\n" not in response and len(response) < max_bytes:
        # Receive one chunk from TCP stream.
        chunk = stream_socket.recv(4096)
        # Stop when server closes connection.
        if not chunk:
            break
        # Append current chunk to running response buffer.
        response += chunk
    # Return collected header bytes (and maybe a small body prefix if server sent it quickly).
    return response


# Build and send HTTP request over TCP and return full response banner for fingerprinting.
def grab_http_banner(host, port=80, timeout=5):
    # Catch transport and DNS exceptions so scanner can continue with other hosts.
    try:
        # Create TCP connection to remote web server endpoint and auto-close it on function exit.
        with _create_tcp_connection(host, port, timeout) as tcp_socket:
            # Re-apply timeout to subsequent recv operations.
            tcp_socket.settimeout(timeout)
            # Build HTTP request that typically triggers server headers like Server and Date.
            request = (
                f"GET / HTTP/1.1\r\n"
                f"Host: {host}\r\n"
                "User-Agent: CN-Fingerprint-Scanner/1.0\r\n"
                "Connection: close\r\n\r\n"
            )
            # Send request bytes through established TCP stream.
            tcp_socket.sendall(request.encode("utf-8"))
            # Read only headers because banner fingerprinting does not require full body download.
            response = _receive_http_headers(tcp_socket)
        # Decode payload as text while ignoring undecodable bytes.
        return response.decode("utf-8", errors="ignore")
    # Return normalized status when packet exchange exceeds timeout budget.
    except socket.timeout:
        return "Timeout"
    # Return DNS failure status when hostname cannot be resolved to an IP.
    except socket.gaierror:
        return "DNS Error"
    # Return generic transport/application exception for diagnostics.
    except Exception as error:
        return f"Error: {error}"


# Read initial FTP server greeting banner from control channel over plain TCP port 21.
def grab_ftp_banner(host, port=21, timeout=5):
    # Catch network exceptions so one failed endpoint does not stop whole scan.
    try:
        # Open TCP connection to FTP control port and auto-close after read.
        with _create_tcp_connection(host, port, timeout) as tcp_socket:
            # Re-apply timeout to banner receive operation.
            tcp_socket.settimeout(timeout)
            # Read server greeting line (typically starts with FTP status code 220).
            banner = tcp_socket.recv(1024).decode("utf-8", errors="ignore")
        # Return banner text for fingerprint parsing.
        return banner
    # Return standardized timeout marker for upper-layer handling.
    except socket.timeout:
        return "Timeout"
    # Return standardized DNS failure marker for upper-layer handling.
    except socket.gaierror:
        return "DNS Error"
    # Return standardized exception marker for upper-layer handling.
    except Exception as error:
        return f"Error: {error}"


# Attempt explicit FTPS (FTP over TLS) by issuing AUTH TLS after plain FTP connect.
def grab_ftps_banner(host, port=21, timeout=5):
    # Catch TLS and socket exceptions so scanner can continue on partial failures.
    try:
        # Open plain FTP control connection before TLS upgrade negotiation.
        with _create_tcp_connection(host, port, timeout) as tcp_socket:
            # Re-apply timeout to subsequent control-channel operations.
            tcp_socket.settimeout(timeout)
            # Read initial FTP greeting from server.
            greeting = tcp_socket.recv(1024).decode("utf-8", errors="ignore")
            # Request explicit TLS upgrade for FTP control channel.
            tcp_socket.sendall(b"AUTH TLS\r\n")
            # Read server response to AUTH TLS command.
            auth_response = tcp_socket.recv(1024).decode("utf-8", errors="ignore")
            # Stop when server refuses TLS upgrade.
            if not auth_response.startswith("234"):
                # Return explicit error marker so unsupported FTPS is classified as unavailable.
                return f"Error: FTPS upgrade rejected ({auth_response.strip()})"
            # Create TLS context with trusted CA defaults for server certificate validation.
            tls_context = ssl.create_default_context()
            # Wrap existing TCP socket in TLS to complete secure control-channel handshake.
            with tls_context.wrap_socket(
                tcp_socket,
                server_hostname=host,
                do_handshake_on_connect=False,
            ) as tls_socket:
                # Re-apply timeout on TLS socket before handshake to avoid indefinite stalls.
                tls_socket.settimeout(timeout)
                # Perform TLS handshake with timeout protection.
                tls_socket.do_handshake()
                # Read negotiated cipher suite from TLS session for evidence of secure transport.
                cipher_name = tls_socket.cipher()[0] if tls_socket.cipher() else "UnknownCipher"
                # Send QUIT command over encrypted control channel for graceful session close.
                tls_socket.sendall(b"QUIT\r\n")
                # Return greeting + AUTH response + cipher to support FTPS service identification.
                return f"{greeting}\n{auth_response}\nTLS Cipher: {cipher_name}"
    # Return explicit TLS error marker when handshake fails.
    except ssl.SSLError:
        return "SSL Error"
    # Return timeout marker when FTPS negotiation takes too long.
    except socket.timeout:
        return "Timeout"
    # Return DNS error marker when host resolution fails.
    except socket.gaierror:
        return "DNS Error"
    # Return generic error marker for remaining exceptions.
    except Exception as error:
        return f"Error: {error}"