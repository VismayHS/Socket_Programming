# Import socket to establish TCP sessions before TLS handshake.
import socket
# Import ssl to perform TLS negotiation for encrypted HTTPS communication.
import ssl


# Connect to HTTPS endpoint, complete TLS handshake, and return full HTTP response banner.
def grab_https_banner(host, port=443, timeout=5):
    # Catch TLS and transport exceptions so scanner continues with other protocols.
    try:
        # Create default TLS context using system CA trust store.
        tls_context = ssl.create_default_context()
        # Open TCP connection to HTTPS port with timeout protection.
        tcp_socket = socket.create_connection((host, port), timeout=timeout)
        # Upgrade TCP connection to TLS while sending SNI for virtual-host certificates.
        tls_socket = tls_context.wrap_socket(tcp_socket, server_hostname=host)
        # Build HTTP request that encourages server to return identifying headers.
        request = (
            f"GET / HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            "User-Agent: CN-Fingerprint-Scanner/1.0\r\n"
            "Connection: close\r\n\r\n"
        )
        # Send encrypted HTTP request over TLS-protected channel.
        tls_socket.sendall(request.encode("utf-8"))
        # Accumulate response bytes from encrypted stream.
        response = b""
        # Receive data until server closes connection.
        while True:
            # Read one chunk from TLS application data stream.
            chunk = tls_socket.recv(4096)
            # Exit when server has sent all response bytes.
            if not chunk:
                break
            # Append chunk to complete response buffer.
            response += chunk
        # Close TLS socket and underlying TCP session.
        tls_socket.close()
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