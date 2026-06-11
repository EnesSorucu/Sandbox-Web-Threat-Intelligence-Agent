"""
Cookie Security Analyzer.
Inspects browser cookies set by the target site and checks for
missing security flags that could enable session hijacking or tracking.

Scoring is context-aware: only flags critical issues, not benign cookies.
"""
import time

def analyze_cookies(cookies: list[dict], has_login_form: bool = False) -> dict:
    """
    Analyze cookies for security best practices.
    Only report a cookie as 'insecure' if it has a session-sensitive name
    (auth, token, session, etc.) AND is missing security flags.
    Regular preference/analytics cookies are treated separately.
    
    has_login_form: True ise sitede şifre/email alanı var demektir,
    cookie güvenlik ihlalleri daha ağır cezalandırılır.
    False ise (form yoksa) cookie riskleri daha hafif değerlendirilir.
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

    # Eğer giriş formu yoksa, oturum/çerez çalınması tehlikesi yoktur.
    # Dolayısıyla çerezleri güvenli sayıp 100 puan veriyoruz.
    if not has_login_form:
        tracking = []
        secure_count = 0
        for cookie in cookies:
            name_lower = cookie.get("name", "").lower()
            is_tracking = any(pattern.lower() in name_lower for pattern in TRACKING_PATTERNS)
            if is_tracking:
                tracking.append({
                    "name": cookie.get("name", ""),
                    "domain": cookie.get("domain", ""),
                    "issues": None
                })
            else:
                secure_count += 1
        return {
            "total_cookies": len(cookies),
            "secure_cookies": secure_count,
            "insecure_cookies": [],
            "tracking_cookies": tracking,
            "score": 100,
        }



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

        # Bağlam Duyarlı Ağırlık: Login formu yoksa, oturum cookie sorunları daha az kritik
        # (Çünkü kullanıcı zaten giriş yapmıyor, çalınacak kimlik bilgisi yok)
        sensitive_weight = 1.0 if has_login_form else 0.5

        # 1. HttpOnly Check (Critical for sensitive cookies) # only https acces to these cookies
        if is_sensitive and not is_tracking and not cookie.get("httpOnly", False):
            issues.append("Missing HttpOnly (XSS risk)")
            total_issues += int(2 * sensitive_weight)

        # 2. Secure Flag Check (Applies to both sensitive and tracking cookies) #ağ katmanındakı dınlemelere karsı korur
        if not cookie.get("secure", False):
            if is_sensitive and not is_tracking:
                issues.append("Missing Secure flag (Sent over HTTP)")
                total_issues += int(2 * sensitive_weight)
            elif is_tracking:
                issues.append("Missing Secure flag (Tracking data sent over HTTP)")
                total_issues += 1 # Tracking over HTTP is also a risk

        # 3. SameSite Check #cookies between websites manages
        same_site = cookie.get("sameSite", "")
        if not same_site:
            if is_sensitive and not is_tracking:
                issues.append("SameSite attribute is missing (Browser default behavior applies)")
                total_issues += int(1 * sensitive_weight)
        elif same_site == "None":
            if is_sensitive and not is_tracking:
                issues.append("SameSite=None (High CSRF risk if not Secure)")
                total_issues += int(2 * sensitive_weight)

        # 4. Domain & Path Coverage Check
        if is_sensitive and not is_tracking:
            if path == "/":
                issues.append("Path=/ (Cookie sent to all paths on the domain)")
                total_issues += int(1 * sensitive_weight)
            if domain.startswith("."):
                issues.append(f"Domain={domain} (Cookie sent to all subdomains)")
                total_issues += int(1 * sensitive_weight)

        # 5. Expires / Max-Age Check
        # Playwright gives expires as unix timestamp. -1 means session cookie.
        expires = cookie.get("expires", -1)
        if is_sensitive and not is_tracking and expires != -1:
            # Check if expiration is more than 30 days (30 * 24 * 60 * 60 seconds)
            if expires - current_time > 2592000:
                issues.append("Sensitive cookie has a very long expiration time (>30 days)")
                total_issues += int(1 * sensitive_weight)

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
    
    # Bağlam Duyarlı Puanlama (Context-Aware Scoring)
    # Sitede giriş formu (şifre/email) varsa cookie ihlalleri ağır cezalandırılır
    # Yoksa (sadece vitrin sitesi) hafif değerlendirilir
    penalty_multiplier = 5 if has_login_form else 2
    score = max(0, 100 - (total_issues * penalty_multiplier))

    return {
        "total_cookies": total,
        "secure_cookies": secure_count,
        "insecure_cookies": insecure,  # Removed [:10] limit
        "tracking_cookies": tracking,
        "score": score,
    }
