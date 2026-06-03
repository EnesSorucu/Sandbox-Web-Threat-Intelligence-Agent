"""
Security Headers Analyzer.
Checks HTTP response headers for essential security configurations.
Missing headers indicate weak security posture — common in phishing sites.
"""


# These are the industry-standard security headers every modern site should have.
SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "description": "Forces browser to use HTTPS (prevents downgrade attacks)",
        "severity": "high",
    },
    "Content-Security-Policy": {
        "description": "Prevents XSS and data injection attacks",
        "severity": "high",
    },
    "X-Frame-Options": {
        "description": "Prevents Clickjacking by disallowing iframes",
        "severity": "medium",
    },
    "X-Content-Type-Options": {
        "description": "Prevents MIME-type sniffing attacks",
        "severity": "medium",
    },
    "Referrer-Policy": {
        "description": "Controls how much referrer info is shared",
        "severity": "low",
    },
    "Permissions-Policy": {
        "description": "Controls browser features (camera, mic, geolocation)",
        "severity": "low",
    },
    "X-XSS-Protection": {
        "description": "Legacy XSS filter (still useful for older browsers)",
        "severity": "low",
    },
}


def analyze_headers(response_headers: dict) -> dict:
    """
    Analyze HTTP response headers for security best practices.

    Args:
        response_headers: dict of HTTP response header name -> value

    Returns:
        dict with:
        - headers_found: list of present security headers
        - headers_missing: list of missing security headers with details
        - score: 0–100 security header score
        - grade: A/B/C/D/F letter grade
    """
    headers_found = []
    headers_missing = []

    # Normalize header names to lowercase for case-insensitive comparison
    normalized = {k.lower(): v for k, v in response_headers.items()}

    for header_name, meta in SECURITY_HEADERS.items():
        key = header_name.lower()
        if key in normalized:
            headers_found.append({
                "name": header_name,
                "value": normalized[key],
                "description": meta["description"],
            })
        else:
            headers_missing.append({
                "name": header_name,
                "severity": meta["severity"],
                "description": meta["description"],
            })

    # Score: each header is worth points proportional to total
    total = len(SECURITY_HEADERS)
    found = len(headers_found)
    score = int((found / total) * 100) if total > 0 else 0

    # Grade
    if score >= 85:
        grade = "A"
    elif score >= 70:
        grade = "B"
    elif score >= 50:
        grade = "C"
    elif score >= 30:
        grade = "D"
    else:
        grade = "F"

    return {
        "headers_found": headers_found,
        "headers_missing": headers_missing,
        "score": score,
        "grade": grade,
    }
