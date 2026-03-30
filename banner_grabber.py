# Import socket for low-level TCP communication used by HTTP and FTP probing.
import socket
# Import ssl so FTP control channel can be upgraded to TLS for FTPS probing.
import ssl


# Build and send HTTP request over TCP and return full response banner for fingerprinting.
def grab_http_banner(host, port=80, timeout=5):
    # Catch transport and DNS exceptions so scanner can continue with other hosts.
    try:
        # Create TCP connection to remote web server endpoint.
        tcp_socket = socket.create_connection((host, port), timeout=timeout)
        # Build HTTP request that typically triggers server headers like Server and Date.
        request = (
            f"GET / HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            "User-Agent: CN-Fingerprint-Scanner/1.0\r\n"
            "Connection: close\r\n\r\n"
        )
        # Send request bytes through established TCP stream.
        tcp_socket.sendall(request.encode("utf-8"))
        # Hold all received payload chunks from server response.
        response = b""
        # Read until remote endpoint closes the stream.
        while True:
            # Receive one chunk from TCP receive buffer.
            chunk = tcp_socket.recv(4096)
            # Stop when no more data is available.
            if not chunk:
                break
            # Append received bytes to full response buffer.
            response += chunk
        # Close socket to release client-side network resources.
        tcp_socket.close()
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
        # Open TCP connection to FTP control port.
        tcp_socket = socket.create_connection((host, port), timeout=timeout)
        # Read server greeting line (typically starts with FTP status code 220).
        banner = tcp_socket.recv(1024).decode("utf-8", errors="ignore")
        # Close control socket after banner read.
        tcp_socket.close()
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
        tcp_socket = socket.create_connection((host, port), timeout=timeout)
        # Read initial FTP greeting from server.
        greeting = tcp_socket.recv(1024).decode("utf-8", errors="ignore")
        # Request explicit TLS upgrade for FTP control channel.
        tcp_socket.sendall(b"AUTH TLS\r\n")
        # Read server response to AUTH TLS command.
        auth_response = tcp_socket.recv(1024).decode("utf-8", errors="ignore")
        # Stop when server refuses TLS upgrade.
        if not auth_response.startswith("234"):
            # Close plain socket after failed FTPS negotiation.
            tcp_socket.close()
            # Return combined transcript for diagnostic visibility.
            return f"{greeting}\n{auth_response}"
        # Create TLS context with trusted CA defaults for server certificate validation.
        tls_context = ssl.create_default_context()
        # Wrap existing TCP socket in TLS to complete secure control-channel handshake.
        tls_socket = tls_context.wrap_socket(tcp_socket, server_hostname=host)
        # Read negotiated cipher suite from TLS session for evidence of secure transport.
        cipher_name = tls_socket.cipher()[0] if tls_socket.cipher() else "UnknownCipher"
        # Send QUIT command over encrypted control channel for graceful session close.
        tls_socket.sendall(b"QUIT\r\n")
        # Close TLS socket and underlying TCP connection.
        tls_socket.close()
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