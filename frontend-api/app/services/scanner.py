"""
Main Scanner / Orchestrator.
Orchestrates the full analysis pipeline:
1. SSL/TLS analysis
2. Domain/WHOIS analysis
3. Playwright scan (browser-based data collection: screenshot, cookies, links, headers)
4. Content analysis (obfuscation, hidden elements)
5. Security Headers analysis
6. Cookie Security analysis
7. Link Tree / Spider analysis
8. AI data preprocessing (data prepared, model not yet connected)
9. Alert generation & overall verdict
"""
from models.schemas import (
    AnalyzeResponse, LogEntry, AIPreprocessedData,
)
from services.ssl_analyzer import analyze_ssl
from services.domain_analyzer import analyze_domain
from services.content_analyzer import analyze_content
from services.playwright_worker import run_playwright_scan
from services.header_analyzer import analyze_headers
from services.cookie_analyzer import analyze_cookies
from services.link_analyzer import analyze_links


async def run_full_scan(url: str) -> AnalyzeResponse:
    """
    Run the complete analysis pipeline on a target URL.
    Returns a fully populated AnalyzeResponse.
    """
    response = AnalyzeResponse(url=url)
    logs: list[LogEntry] = []

    # =============================
    # PHASE 1: SSL/TLS Analysis
    # =============================
    logs.append(LogEntry(level="INFO", message="Checking SSL/TLS certificate..."))
    ssl_result = analyze_ssl(url)
    response.ssl = ssl_result

    if ssl_result.has_ssl:
        logs.append(LogEntry(
            level="INFO",
            message=f"SSL certificate found. Issuer: {ssl_result.issuer or 'N/A'}, Age: {ssl_result.age_days} days"
        ))
    elif ssl_result.error:
        logs.append(LogEntry(level="WARN", message=f"SSL issue: {ssl_result.error}"))
    else:
        logs.append(LogEntry(level="WARN", message="No SSL certificate detected."))

    # =============================
    # PHASE 2: Domain/WHOIS Analysis
    # =============================
    logs.append(LogEntry(level="INFO", message="Running WHOIS & domain analysis..."))
    domain_result = analyze_domain(url)
    response.domain = domain_result

    if domain_result.age_days is not None:
        logs.append(LogEntry(
            level="INFO",
            message=f"Domain: {domain_result.domain}, Age: {domain_result.age_days} days, Registrar: {domain_result.registrar or 'N/A'}"
        ))

    if domain_result.is_typosquatting:
        logs.append(LogEntry(
            level="ALERT",
            message=f"TYPOSQUATTING detected! Domain mimics '{domain_result.typosquatting_target}'"
        ))

    if domain_result.is_new_domain:
        logs.append(LogEntry(
            level="WARN",
            message=f"New domain! Registered only {domain_result.age_days} days ago."
        ))

    if domain_result.error:
        logs.append(LogEntry(level="WARN", message=f"WHOIS: {domain_result.error}"))

    # =============================
    # PHASE 3: Playwright Browser Scan
    # =============================
    scan_data = await run_playwright_scan(url, logs)

    if scan_data.get("error"):
        response.error = scan_data["error"]
        response.overall_status = "error"
        response.overall_label = "Scan Failed"
        response.overall_description = f"Could not complete scan: {scan_data['error']}"
        response.logs = logs
        return response

    response.forms = scan_data["forms"]
    response.download = scan_data["download"]
    response.screenshot_b64 = scan_data.get("screenshot_b64", "")

    # =============================
    # PHASE 4: Content Analysis
    # =============================
    logs.append(LogEntry(level="INFO", message="Analyzing page content for obfuscation..."))
    content_result = analyze_content(
        page_source=scan_data["page_source"],
        js_contents=scan_data["js_contents"],
        hidden_elements=scan_data["hidden_elements"],
        scripts=scan_data["scripts"],
        page_domain=scan_data["page_domain"],
    )
    response.content = content_result

    if content_result.obfuscation_keywords_found:
        logs.append(LogEntry(
            level="WARN",
            message=f"Obfuscation indicators found: {', '.join(content_result.obfuscation_keywords_found)}"
        ))

    if content_result.external_scripts:
        logs.append(LogEntry(
            level="INFO",
            message=f"External scripts detected: {len(content_result.external_scripts)} / {content_result.total_scripts} total"
        ))

    # =============================
    # PHASE 5: Security Headers Analysis
    # =============================
    logs.append(LogEntry(level="INFO", message="Analyzing HTTP security headers..."))
    headers_result = analyze_headers(scan_data.get("response_headers", {}))
    response.security_headers = headers_result

    found_count = len(headers_result.get("headers_found", []))
    missing_count = len(headers_result.get("headers_missing", []))
    grade = headers_result.get("grade", "?")
    logs.append(LogEntry(
        level="INFO" if grade in ["A", "B"] else "WARN",
        message=f"Security Headers: {found_count} found, {missing_count} missing — Grade: {grade}"
    ))

    # =============================
    # PHASE 6: Cookie Security Analysis
    # =============================
    logs.append(LogEntry(level="INFO", message="Analyzing cookie security..."))
    cookie_result = analyze_cookies(scan_data.get("cookies", []))
    response.cookie_analysis = cookie_result

    total_cookies = cookie_result.get("total_cookies", 0)
    insecure_count = len(cookie_result.get("insecure_cookies", []))
    tracking_count = len(cookie_result.get("tracking_cookies", []))
    if total_cookies > 0:
        logs.append(LogEntry(
            level="INFO" if insecure_count == 0 else "WARN",
            message=f"Cookies: {total_cookies} total, {insecure_count} insecure, {tracking_count} tracking"
        ))
    else:
        logs.append(LogEntry(level="INFO", message="No cookies detected."))

    # =============================
    # PHASE 7: Link Tree / Spider Analysis
    # =============================
    logs.append(LogEntry(level="INFO", message="Analyzing page link tree..."))
    link_result = analyze_links(
        links=scan_data.get("links", []),
        page_domain=scan_data["page_domain"],
    )
    response.link_analysis = link_result

    total_links = link_result.get("total_links", 0)
    ext_links = link_result.get("external_links", 0)
    dl_links = len(link_result.get("download_links", []))
    suspicious_links = len(link_result.get("suspicious_links", []))
    logs.append(LogEntry(
        level="INFO",
        message=f"Links: {total_links} total ({ext_links} external, {dl_links} download, {suspicious_links} misleading)"
    ))

    # =============================
    # PHASE 8: AI Data Preprocessing
    # =============================
    logs.append(LogEntry(level="INFO", message="Preparing data for AI models..."))

    page_text = scan_data.get("page_text", "")
    ai_data = AIPreprocessedData()
    ai_data.page_text = page_text[:5000]  # Truncate for safety
    ai_data.page_text_length = len(page_text)
    ai_data.ai_service_available = True  # Explicitly enabling AI service flag for UI rendering

    # Build form features vector for future AI model
    forms = response.forms
    ai_data.form_features = {
        "total_forms": forms.total_forms,
        "suspicious_forms": forms.suspicious_forms,
        "has_password_field": any(f.has_password_field for f in forms.forms),
        "has_email_field": any(f.has_email_field for f in forms.forms),
        "external_redirect_count": sum(1 for f in forms.forms if f.redirects_external),
        "external_script_ratio": content_result.external_script_ratio,
        "hidden_element_count": content_result.hidden_element_count,
        "obfuscation_score": content_result.obfuscation_score,
    }

    # Connect to the AI Inference microservice to process NLP and DOM anomaly models
    import httpx
    try:
        async with httpx.AsyncClient() as client:
            ai_req_payload = {
                "scraped_text": ai_data.page_text,
                "dom_features": ai_data.form_features
            }
            
            # API çağrısı (İlk çalışmada modelin RAM'e yüklenmesi 15-20 saniye sürebilir, timeout uzatıldı)
            ai_resp = await client.post("http://ai-service:8001/analyze", json=ai_req_payload, timeout=30.0)
            if ai_resp.status_code == 200:
                ai_json = ai_resp.json()
                ai_data.phishing_text_score = float(ai_json.get("phishing_text_risk_score", 0.0)) * 100
                ai_data.form_anomaly_score = float(ai_json.get("dom_anomaly_score", 0.0)) * 100
            else:
                logs.append(LogEntry(level="WARN", message=f"ai-service returned status {ai_resp.status_code}: {ai_resp.text}"))
                ai_data.phishing_text_score = 0.0
                ai_data.form_anomaly_score = 0.0
    except Exception as e:
        logs.append(LogEntry(level="WARN", message=f"Failed to connect to ai-service: {str(e)}"))
        ai_data.phishing_text_score = 0.0
        ai_data.form_anomaly_score = 0.0

    response.ai_data = ai_data

    logs.append(LogEntry(
        level="INFO",
        message=f"Page text extracted ({ai_data.page_text_length} chars). AI service: {'connected' if ai_data.ai_service_available else 'not connected (placeholder)'}"
    ))

    # =============================
    # PHASE 9: Generate Alerts & Verdict
    # =============================
    logs.append(LogEntry(level="INFO", message="Generating threat verdict..."))
    alerts = []
    threat_score = 0  # 0 = safe, higher = more dangerous

    # Drive-by download = instant MALICIOUS
    if response.download.download_attempted:
        alerts.append({
            "type": "danger",
            "icon": "fa-download",
            "text": f"Automatic Download Blocked ({response.download.download_filename})"
        })
        threat_score += 100

    # SSL issues
    if ssl_result.is_suspicious and ssl_result.age_days is not None:
        alerts.append({
            "type": "caution",
            "icon": "fa-certificate",
            "text": f"New SSL Certificate ({ssl_result.age_days} day(s) old — suspicious on older domain)"
        })
        threat_score += 25

    if not ssl_result.has_ssl:
        alerts.append({
            "type": "warning",
            "icon": "fa-lock-open",
            "text": "No SSL/TLS - Connection is NOT encrypted"
        })
        threat_score += 15

    # Domain issues
    if domain_result.is_typosquatting:
        alerts.append({
            "type": "warning",
            "icon": "fa-masks-theater",
            "text": f"Brand Mimicking Detected (looks like '{domain_result.typosquatting_target}')"
        })
        threat_score += 40

    if domain_result.is_new_domain:
        alerts.append({
            "type": "caution",
            "icon": "fa-clock",
            "text": f"Young Domain ({domain_result.age_days} days old — less than 1 year)"
        })
        threat_score += 25

    if domain_result.registrar_suspicious:
        alerts.append({
            "type": "caution",
            "icon": "fa-user-secret",
            "text": "Registrar uses anonymity/privacy protection (Common in phishing)"
        })
        threat_score += 15

    if domain_result.is_expiration_near:
        alerts.append({
            "type": "caution",
            "icon": "fa-hourglass-end",
            "text": "Domain expires very soon (< 30 days)"
        })
        threat_score += 10

    # Content issues
    if content_result.obfuscation_score >= 40:
        alerts.append({
            "type": "warning",
            "icon": "fa-eye-slash",
            "text": f"JS Obfuscation Detected (score: {content_result.obfuscation_score}%)"
        })
        threat_score += 25

    if content_result.hidden_element_count > 3:
        alerts.append({
            "type": "caution",
            "icon": "fa-eye-low-vision",
            "text": f"{content_result.hidden_element_count} Hidden Elements Found"
        })
        threat_score += 10

    # Security Headers issues
    if headers_result.get("grade") == "F":
        alerts.append({
            "type": "warning",
            "icon": "fa-shield-halved",
            "text": f"Critical: No Security Headers (Grade: F — site has zero protection)"
        })
        threat_score += 25
    elif headers_result.get("grade") == "D":
        alerts.append({
            "type": "caution",
            "icon": "fa-shield-halved",
            "text": f"Weak Security Headers (Grade: D)"
        })
        threat_score += 15

    # Cookie issues
    if insecure_count > 3:
        alerts.append({
            "type": "caution",
            "icon": "fa-cookie-bite",
            "text": f"{insecure_count} Insecure Cookies Detected"
        })
        threat_score += 5

    # Link issues
    if suspicious_links > 0:
        alerts.append({
            "type": "warning",
            "icon": "fa-link-slash",
            "text": f"{suspicious_links} Misleading Link(s) Found (text/href mismatch)"
        })
        threat_score += 20

    if dl_links > 0:
        alerts.append({
            "type": "caution",
            "icon": "fa-file-arrow-down",
            "text": f"{dl_links} Download Link(s) on Page"
        })
        threat_score += 10

    # Form issues
    if forms.suspicious_forms > 0:
        for f in forms.forms:
            if f.redirects_external:
                alerts.append({
                    "type": "danger",
                    "icon": "fa-arrow-right-from-bracket",
                    "text": f"Form redirects to external domain: {f.external_domain}"
                })
                threat_score += 30

    response.alerts = alerts

    # Determine overall status
    if threat_score >= 80:
        response.overall_status = "malicious"
        response.overall_label = "Malicious Site Detected"
        response.overall_description = "HIGH RISK - DO NOT PROCEED"
    elif threat_score >= 30:
        response.overall_status = "suspicious"
        response.overall_label = "Suspicious Activity Detected"
        response.overall_description = "PROCEED WITH CAUTION"
    else:
        response.overall_status = "safe"
        response.overall_label = "Site Appears Safe"
        response.overall_description = "No major threats detected"

    logs.append(LogEntry(level="SUCCESS", message=f"Analysis complete. Verdict: {response.overall_status.upper()} (score: {threat_score})"))
    response.logs = logs

    return response
