# Import socket to establish TCP sessions before TLS handshake.
import socket
# Import ssl to perform TLS negotiation for encrypted HTTPS communication.
import ssl
# Import time to enforce total connection deadlines across multiple resolved IPs.
import time


# Create TCP connection with a hard total timeout even when host resolves to many IP addresses.
def _create_tcp_connection(host, port, timeout):
    # Compute absolute deadline so all address attempts share one timeout budget.
    deadline = time.monotonic() + timeout
    # Keep last connection failure for final diagnostic raise path.
    last_error = socket.timeout("Connection timed out")
    # Resolve host to candidate IPv4/IPv6 endpoints.
    address_candidates = socket.getaddrinfo(
        host,
        port,
        family=socket.AF_UNSPEC,
        type=socket.SOCK_STREAM,
    )
    # Attempt each candidate endpoint until one connects or deadline is exhausted.
    for family, socktype, proto, _, sockaddr in address_candidates:
        # Compute remaining timeout before next attempt.
        remaining = deadline - time.monotonic()
        # Stop when no timeout budget remains.
        if remaining <= 0:
            break
        # Create socket for this candidate address.
        tcp_socket = socket.socket(family, socktype, proto)
        # Attempt connect and close socket on failure.
        try:
            # Apply remaining timeout budget to this attempt.
            tcp_socket.settimeout(remaining)
            # Connect to selected endpoint.
            tcp_socket.connect(sockaddr)
            # Return connected socket for TLS wrapping.
            return tcp_socket
        except Exception as error:
            # Keep latest failure for final diagnostics.
            last_error = error
            # Close failed socket attempt.
            tcp_socket.close()
    # Raise timeout when budget is exhausted.
    if deadline - time.monotonic() <= 0:
        raise socket.timeout("Connection timed out")
    # Raise final connection failure from candidate attempts.
    raise last_error


# Receive only HTTP response headers so HTTPS banner extraction is fast and lightweight.
def _receive_http_headers(stream_socket, max_bytes=16384):
    # Start with an empty byte buffer for incremental TLS reads.
    response = b""
    # Continue until header terminator appears or byte budget is consumed.
    while b"\r\n\r\n" not in response and len(response) < max_bytes:
        # Read one chunk from encrypted stream.
        chunk = stream_socket.recv(4096)
        # Stop if server closes connection.
        if not chunk:
            break
        # Append received bytes to complete response fragment.
        response += chunk
    # Return captured header bytes (plus any small body prefix already received).
    return response


# Connect to HTTPS endpoint, complete TLS handshake, and return full HTTP response banner.
def grab_https_banner(host, port=443, timeout=5):
    # Catch TLS and transport exceptions so scanner continues with other protocols.
    try:
        # Create default TLS context using system CA trust store.
        tls_context = ssl.create_default_context()
        # Open TCP connection to HTTPS port with timeout protection.
        with _create_tcp_connection(host, port, timeout) as tcp_socket:
            # Re-apply timeout for post-connect operations.
            tcp_socket.settimeout(timeout)
            # Upgrade TCP connection to TLS while sending SNI for virtual-host certificates.
            with tls_context.wrap_socket(
                tcp_socket,
                server_hostname=host,
                do_handshake_on_connect=False,
            ) as tls_socket:
                # Re-apply timeout on TLS socket before handshake to avoid indefinite stalls.
                tls_socket.settimeout(timeout)
                # Perform TLS handshake with timeout protection.
                tls_socket.do_handshake()
                # Build HTTP request that encourages server to return identifying headers.
                request = (
                    f"GET / HTTP/1.1\r\n"
                    f"Host: {host}\r\n"
                    "User-Agent: CN-Fingerprint-Scanner/1.0\r\n"
                    "Connection: close\r\n\r\n"
                )
                # Send encrypted HTTP request over TLS-protected channel.
                tls_socket.sendall(request.encode("utf-8"))
                # Read only headers because banner fingerprinting does not need full HTML body.
                response = _receive_http_headers(tls_socket)
        # Decode response bytes for header-based fingerprint extraction.
        return response.decode("utf-8", errors="ignore")
    # Return standardized TLS failure marker.
    except ssl.SSLError:
        return "SSL Error"
    # Return standardized timeout marker.
    except socket.timeout:
        return "Timeout"
    # Return standardized DNS resolution failure marker.
    except socket.gaierror:
        return "DNS Error"
    # Return generic error marker with exception context.
    except Exception as error:
        return f"Error: {error}"