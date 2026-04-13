# Import regex module for extracting product/version signatures from protocol banners.
import re


# Analyze raw protocol banner text and infer server product name with optional version.
def identify_service(banner):
    # Return unavailable when no banner text is present.
    if not banner:
        return "Unavailable"
    # Remove leading/trailing whitespace so status checks are not affected by line endings.
    cleaned_banner = banner.strip()
    # Normalize text for case-insensitive matching across known failure markers.
    lowered_banner = cleaned_banner.lower()
    # Treat explicit transport failure values as unavailable service state.
    if lowered_banner in {"timeout", "dns error", "ssl error"}:
        return "Unavailable"
    # Treat generic exception text emitted by probe functions as unavailable state.
    if lowered_banner.startswith("error:"):
        return "Unavailable"
    # Prefer explicit HTTP Server header because it is the strongest direct identity source.
    for line in cleaned_banner.splitlines():
        # Remove surrounding whitespace from header line.
        cleaned_line = line.strip()
        # Return first Server header discovered in response.
        if cleaned_line.lower().startswith("server:"):
            return cleaned_line
    # Detect FTP-style greeting lines with code 220 and capture server descriptor text.
    ftp_match = re.search(r"^220[\-\s](.+)$", cleaned_banner, re.MULTILINE)
    # Detect explicit FTPS upgrade evidence when probe recorded negotiated TLS cipher details.
    if "tls cipher:" in lowered_banner:
        # Return FTPS-tagged greeting when FTP welcome descriptor is available.
        if ftp_match:
            return f"{ftp_match.group(1).strip()} (FTPS)"
        # Fall back to generic FTPS status when greeting is not present.
        return "FTPS (TLS Enabled)"
    # Return parsed FTP descriptor if greeting pattern was found.
    if ftp_match:
        return ftp_match.group(1).strip()
    # Define common web and FTP product signatures expected in banners.
    service_signatures = [
        "Apache",  # Apache HTTP Server signature used in many Linux web deployments.
        "Nginx",  # Nginx reverse proxy/web server signature common in modern stacks.
        "Microsoft-IIS",  # IIS signature for Windows-hosted web services.
        "LiteSpeed",  # LiteSpeed web server signature often seen in shared hosting.
        "OpenResty",  # OpenResty signature for Nginx + Lua web platforms.
        "Caddy",  # Caddy server signature for automatic TLS-enabled deployments.
        "gunicorn",  # Gunicorn Python WSGI server signature for backend web apps.
        "uvicorn",  # Uvicorn ASGI server signature for async Python services.
        "ProFTPD",  # ProFTPD signature for FTP/FTPS file transfer services.
        "vsFTPd",  # vsFTPd signature for lightweight FTP server deployments.
        "Pure-FTPd",  # Pure-FTPd signature for secure FTP service deployments.
    ]
    # Search each known signature in banner text.
    for signature in service_signatures:
        # Attempt precise product/version extraction first.
        version_match = re.search(
            rf"{re.escape(signature)}/[A-Za-z0-9\.\-_]+", cleaned_banner, re.IGNORECASE
        )
        # Return full product/version token when available.
        if version_match:
            return version_match.group(0)
        # Fall back to product name when version is hidden.
        if signature.lower() in lowered_banner:
            return signature
    # Return unknown when no recognizable signature is present.
    return "Unknown"