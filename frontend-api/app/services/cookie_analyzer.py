"""
Cookie Security Analyzer.
Inspects browser cookies set by the target site and checks for
missing security flags that could enable session hijacking or tracking.

Scoring is context-aware: only flags critical issues, not benign cookies.
"""
import time

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

    # Extended tracking cookie patterns
    TRACKING_PATTERNS = [
        "_ga", "_gid", "_gat", "__utma", "__utmb", "__utmc", "__utmz",  # Google Analytics
        "_fbp", "_fbc",                                                   # Facebook
        "IDE", "DSID", "NID",                                             # Google Ads / DoubleClick
        "_pin_unauth",                                                     # Pinterest
        "personalization_id",                                              # Twitter
        "criteo", "amazon", "adobe", "yandex", "mc", "uid", "visitor",     # General trackers
        "_hj", "_ym", "amplitude", "mixpanel", "hubspot"                   # Analytics
    ]

    # Session/auth-related cookie names (Specific frameworks + general keywords)
    SESSION_SENSITIVE_NAMES = [
        "jsessionid", "phpsessid", "asp.net_sessionid", "connect.sid",
        "x-auth-token", "api_key", "csrf_token", "csrftoken", "_session_id",
        "session", "sess", "auth", "token", "jwt", "login",
        "account", "user", "admin", "csrf", "sid", "key",
        "credential", "identity", "access", "refresh",
    ]

    insecure = []
    tracking = []
    secure_count = 0
    total_issues = 0 # To calculate a more realistic score

    current_time = time.time()

    for cookie in cookies:
        name = cookie.get("name", "")
        name_lower = name.lower()
        domain = cookie.get("domain", "")
        path = cookie.get("path", "")
        issues = []

        is_tracking = False
        # Check if it's a known tracking cookie
        for pattern in TRACKING_PATTERNS:
            if pattern.lower() in name_lower:
                is_tracking = True
                break

        is_sensitive = any(kw in name_lower for kw in SESSION_SENSITIVE_NAMES)

        # 1. HttpOnly Check (Critical for sensitive cookies)
        if is_sensitive and not is_tracking and not cookie.get("httpOnly", False):
            issues.append("Missing HttpOnly (XSS risk)")
            total_issues += 2

        # 2. Secure Flag Check (Applies to both sensitive and tracking cookies)
        if not cookie.get("secure", False):
            if is_sensitive and not is_tracking:
                issues.append("Missing Secure flag (Sent over HTTP)")
                total_issues += 2
            elif is_tracking:
                issues.append("Missing Secure flag (Tracking data sent over HTTP)")
                total_issues += 1 # Tracking over HTTP is also a risk

        # 3. SameSite Check
        same_site = cookie.get("sameSite", "")
        if not same_site:
            if is_sensitive and not is_tracking:
                issues.append("SameSite attribute is missing (Browser default behavior applies)")
                total_issues += 1
        elif same_site == "None":
            if is_sensitive and not is_tracking:
                issues.append("SameSite=None (High CSRF risk if not Secure)")
                total_issues += 2

        # 4. Domain & Path Coverage Check
        if is_sensitive and not is_tracking:
            if path == "/":
                issues.append("Path=/ (Cookie sent to all paths on the domain)")
                total_issues += 1
            if domain.startswith("."):
                issues.append(f"Domain={domain} (Cookie sent to all subdomains)")
                total_issues += 1

        # 5. Expires / Max-Age Check
        # Playwright gives expires as unix timestamp. -1 means session cookie.
        expires = cookie.get("expires", -1)
        if is_sensitive and not is_tracking and expires != -1:
            # Check if expiration is more than 30 days (30 * 24 * 60 * 60 seconds)
            if expires - current_time > 2592000:
                issues.append("Sensitive cookie has a very long expiration time (>30 days)")
                total_issues += 1

        # Categorize
        if is_tracking:
            tracking.append({
                "name": name,
                "domain": domain,
                "issues": issues if issues else None
            })
            if issues:
                insecure.append({
                    "name": name,
                    "domain": domain,
                    "issues": issues,
                })
        elif is_sensitive:
            if issues:
                insecure.append({
                    "name": name,
                    "domain": domain,
                    "issues": issues,
                })
            else:
                secure_count += 1
        else:
            # Neither tracking nor explicitly sensitive, but let's check basic Secure flag for general hygiene
            if not cookie.get("secure", False):
                # Minor issue for normal cookies
                pass
            else:
                secure_count += 1

    total = len(cookies)
    
    # Realistic scoring based on total issues
    # Max score is 100, each issue deducts points based on its weight (total_issues)
    score = max(0, 100 - (total_issues * 5))

    return {
        "total_cookies": total,
        "secure_cookies": secure_count,
        "insecure_cookies": insecure,  # Removed [:10] limit
        "tracking_cookies": tracking,
        "score": score,
    }
