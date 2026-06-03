"""
Cookie Security Analyzer.
Inspects browser cookies set by the target site and checks for
missing security flags that could enable session hijacking or tracking.

Scoring is context-aware: only flags critical issues, not benign cookies.
"""


def analyze_cookies(cookies: list[dict]) -> dict:
    """
    Analyze cookies for security best practices.
    Only report a cookie as 'insecure' if it has a session-sensitive name
    (auth, token, session, etc.) AND is missing security flags.
    Regular preference/analytics cookies are treated separately.
    """
    if not cookies:
        return {
            "total_cookies": 0,
            "secure_cookies": 0,
            "insecure_cookies": [],
            "tracking_cookies": [],
            "score": 100,
        }

    # Known tracking cookie name patterns
    TRACKING_PATTERNS = [
        "_ga", "_gid", "_gat", "__utma", "__utmb", "__utmc", "__utmz",  # Google Analytics
        "_fbp", "_fbc",                                                   # Facebook
        "IDE", "DSID", "NID",                                             # Google Ads / DoubleClick
        "_pin_unauth",                                                     # Pinterest
        "personalization_id",                                              # Twitter
    ]

    # Session/auth-related cookie name keywords that MUST be secure
    SESSION_SENSITIVE_KEYWORDS = [
        "session", "sess", "auth", "token", "jwt", "login",
        "account", "user", "admin", "csrf", "sid", "key",
        "credential", "identity", "access", "refresh",
    ]

    insecure = []
    tracking = []
    secure_count = 0

    for cookie in cookies:
        name = cookie.get("name", "")
        name_lower = name.lower()
        issues = []

        is_tracking = False
        # Check if it's a known tracking cookie (skip security check for these)
        for pattern in TRACKING_PATTERNS:
            if pattern.lower() in name_lower:
                tracking.append({
                    "name": name,
                    "domain": cookie.get("domain", ""),
                })
                is_tracking = True
                break

        # Only check security flags for session/auth sensitive cookies
        is_sensitive = any(kw in name_lower for kw in SESSION_SENSITIVE_KEYWORDS)
        if is_sensitive and not is_tracking:
            # HttpOnly is critical for auth cookies (prevents JS theft)
            if not cookie.get("httpOnly", False):
                issues.append("Missing HttpOnly")

            # Secure flag is critical (prevents sending over HTTP)
            if not cookie.get("secure", False):
                issues.append("Missing Secure flag")

            # SameSite=None is risky for CSRF on auth cookies
            same_site = cookie.get("sameSite", "")
            if same_site == "None":
                issues.append("SameSite=None (CSRF risk)")

            if issues:
                insecure.append({
                    "name": name,
                    "domain": cookie.get("domain", ""),
                    "issues": issues,
                })
            else:
                secure_count += 1
        else:
            # Non-sensitive cookie: considered ok
            secure_count += 1

    total = len(cookies)
    # Score based only on sensitive cookies
    sensitive_total = len(insecure) + secure_count
    score = int(((sensitive_total - len(insecure)) / sensitive_total) * 100) if sensitive_total > 0 else 100

    return {
        "total_cookies": total,
        "secure_cookies": secure_count,
        "insecure_cookies": insecure[:10],
        "tracking_cookies": tracking,
        "score": score,
    }
