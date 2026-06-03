"""
SSL/TLS Certificate Analyzer.
Extracts certificate details and checks for suspicious patterns
(e.g. newly issued certs).
"""
import ssl
import socket
from datetime import datetime, timezone
from urllib.parse import urlparse
from models.schemas import SSLInfo


def analyze_ssl(url: str) -> SSLInfo:
    """
    Connect to the target host via SSL, extract the certificate,
    and determine if it looks suspicious.
    """
    result = SSLInfo()

    try:
        parsed = urlparse(url)
        hostname = parsed.hostname
        port = parsed.port or 443

        if not hostname:
            result.error = "Could not parse hostname from URL"
            return result

        # Create an SSL context and fetch the certificate
        ctx = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()

        if not cert:
            result.error = "No certificate returned by server"
            return result

        result.has_ssl = True

        # Parse issuer
        issuer_parts = []
        for rdn in cert.get("issuer", ()):
            for attr_type, attr_value in rdn:
                issuer_parts.append(f"{attr_type}={attr_value}")
        result.issuer = ", ".join(issuer_parts)

        # Parse subject
        subject_parts = []
        for rdn in cert.get("subject", ()):
            for attr_type, attr_value in rdn:
                subject_parts.append(f"{attr_type}={attr_value}")
        result.subject = ", ".join(subject_parts)

        # Parse dates
        not_before_str = cert.get("notBefore", "")
        not_after_str = cert.get("notAfter", "")

        if not_before_str:
            not_before = datetime.strptime(not_before_str, "%b %d %H:%M:%S %Y %Z")
            result.not_before = not_before.strftime("%Y-%m-%d %H:%M:%S")
            age = datetime.now(timezone.utc) - not_before.replace(tzinfo=timezone.utc)
            result.age_days = age.days

            # Flag certificates less than 3 days old as suspicious
            if age.days <= 3:
                result.is_suspicious = True

        if not_after_str:
            not_after = datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z")
            result.not_after = not_after.strftime("%Y-%m-%d %H:%M:%S")

    except ssl.SSLCertVerificationError as e:
        result.has_ssl = False
        result.is_suspicious = True
        result.error = f"SSL verification failed: {e}"
    except socket.timeout:
        result.error = "Connection timed out"
    except socket.gaierror:
        result.error = "DNS resolution failed"
    except Exception as e:
        result.error = f"SSL check error: {type(e).__name__}: {e}"

    return result
