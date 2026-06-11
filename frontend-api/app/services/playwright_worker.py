"""
Playwright Worker.
Operates a headless Chromium browser to safely visit target URLs,
capture DOM data, detect drive-by downloads, take screenshots,
extract cookies, collect all links, and capture HTTP headers.
"""
import asyncio
import base64
from urllib.parse import urlparse
from playwright.async_api import async_playwright
from models.schemas import DownloadDetection, FormInfo, FormAnalysis, LogEntry


async def run_playwright_scan(url: str, logs: list[LogEntry]) -> dict:
    """
    Visit the target URL in a headless Chromium browser.

    Returns a dict with all collected data for downstream analyzers.
    """
    parsed = urlparse(url)
    page_domain = parsed.hostname or ""

    download_result = DownloadDetection()
    forms_result = FormAnalysis()

    page_source = ""
    page_text = ""
    js_contents = []
    hidden_elements = []
    scripts_info = []
    final_url = url
    screenshot_b64 = ""
    cookies_raw = []
    links_raw = []
    response_headers = {}

    logs.append(LogEntry(level="INFO", message="Launching headless Chromium browser..."))

    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        context = await browser.new_context(
            ignore_https_errors=True,
            user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        )

        page = await context.new_page()

        # --- Drive-by Download Detection ---
        download_triggered = False
        download_filename = None

        def on_download(download):
            nonlocal download_triggered, download_filename
            download_triggered = True
            download_filename = download.suggested_filename
            logs.append(LogEntry(
                level="ALERT",
                message=f"Unexpected download triggered ({download_filename}) -> BLOCKED."
            ))
            # Cancel the download immediately
            asyncio.ensure_future(download.cancel())

        page.on("download", on_download)

        # --- Navigate to URL ---
        logs.append(LogEntry(level="INFO", message=f"Navigating to {url}..."))

        try:
            response = await page.goto(url, wait_until="domcontentloaded", timeout=30000)
            final_url = page.url
            logs.append(LogEntry(level="INFO", message=f"Page loaded (status: {response.status if response else 'unknown'})"))

            # Capture HTTP response headers
            if response:
                response_headers = dict(response.headers) if response.headers else {}
                logs.append(LogEntry(level="INFO", message=f"Captured {len(response_headers)} HTTP response headers."))

        except Exception as e:
            logs.append(LogEntry(level="ALERT", message=f"Navigation error: {type(e).__name__}: {e}"))
            await browser.close()
            return {
                "page_source": "",
                "page_text": "",
                "js_contents": [],
                "hidden_elements": [],
                "scripts": [],
                "forms": forms_result,
                "download": download_result,
                "final_url": final_url,
                "page_domain": page_domain,
                "screenshot_b64": "",
                "cookies": [],
                "links": [],
                "response_headers": {},
                "error": str(e),
            }

        # Wait 5 seconds to catch any drive-by downloads
        logs.append(LogEntry(level="INFO", message="Monitoring for automatic downloads (5s)..."))
        await asyncio.sleep(5)

        download_result.download_attempted = download_triggered
        download_result.download_filename = download_filename
        download_result.blocked = download_triggered

        # --- Take Screenshot ---
        logs.append(LogEntry(level="INFO", message="Capturing page screenshot..."))
        try:
            screenshot_bytes = await page.screenshot(full_page=False, type="png")
            screenshot_b64 = base64.b64encode(screenshot_bytes).decode("utf-8")
            logs.append(LogEntry(level="SUCCESS", message="Screenshot captured successfully."))
        except Exception as e:
            logs.append(LogEntry(level="WARN", message=f"Screenshot failed: {e}"))

        # --- Extract page source ---
        logs.append(LogEntry(level="INFO", message="Capturing DOM structure..."))
        page_source = await page.content()

        # --- Extract visible text ---
        page_text = await page.evaluate("() => document.body ? document.body.innerText : ''")

        # --- Extract inline JS ---
        js_contents = await page.evaluate("""
            () => {
                const scripts = document.querySelectorAll('script:not([src])');
                return Array.from(scripts).map(s => s.textContent || '');
            }
        """)

        # --- Extract script tags info ---
        scripts_info = await page.evaluate("""
            () => {
                const scripts = document.querySelectorAll('script');
                return Array.from(scripts).map(s => ({
                    src: s.src || '',
                    has_inline: !s.src && (s.textContent || '').length > 0
                }));
            }
        """)

        # --- Detect hidden elements ---
        logs.append(LogEntry(level="INFO", message="Scanning for hidden elements..."))
        hidden_elements = await page.evaluate("""
            (pageHost) => {
                const all = document.querySelectorAll('form, a, input, iframe');
                const hidden = [];
                const popularBrands = ["google", "youtube", "facebook", "twitter", "instagram", "linkedin", "apple", "microsoft", "spotify", "netflix"];
                
                all.forEach(el => {
                    const style = window.getComputedStyle(el);
                    const isHidden = style.display === 'none' || style.visibility === 'hidden' || style.opacity === '0' || el.type === 'hidden';
                    
                    if (isHidden) {
                        const tag = el.tagName.toLowerCase();
                        let isSuspicious = false;
                        let info = el.tagName;
                        
                        if (tag === 'iframe') {
                            isSuspicious = true; // Bütün gizli iframe'ler şüpheli olabilir (clickjacking)
                            info += ' src=' + (el.src || 'about:blank');
                        } else if (tag === 'form') {
                            // Sadece içinde input olan gizli formlar şüphelidir
                            const hasInputs = el.querySelectorAll('input').length > 0;
                            if (hasInputs) {
                                isSuspicious = true;
                                info += ' action=' + (el.action || 'self');
                            }
                        } else if (tag === 'input') {
                            // Sadece gizli şifre veya email alanları şüphelidir (autofill theft)
                            const type = (el.type || '').toLowerCase();
                            if (type === 'password' || type === 'email') {
                                isSuspicious = true;
                                info += ' type=' + type + (el.name ? ' name=' + el.name : '');
                            }
                        } else if (tag === 'a' && el.href) {
                            // Sadece dış domainlere giden ve popüler olmayan linkler şüphelidir
                            try {
                                const url = new URL(el.href);
                                const linkHost = url.hostname.toLowerCase();
                                if (linkHost && !linkHost.includes(pageHost)) {
                                    // Popüler markalara giden linkler hariç
                                    const isPopular = popularBrands.some(brand => linkHost.includes(brand));
                                    if (!isPopular) {
                                        isSuspicious = true;
                                        info += ' href=' + el.href;
                                    }
                                }
                            } catch(e) {}
                        }
                        
                        if (isSuspicious) {
                            hidden.push({ tag: tag, info: info });
                        }
                    }
                });
                return hidden;
            }
        """, urlparse(url).hostname or "")

        if hidden_elements:
            logs.append(LogEntry(
                level="WARN",
                message=f"Found {len(hidden_elements)} hidden elements (display:none/visibility:hidden)"
            ))
        else:
            logs.append(LogEntry(level="INFO", message="No suspicious hidden elements found."))

        # --- Extract All Links (Spider) ---
        logs.append(LogEntry(level="INFO", message="Extracting all page links (spider mode)..."))
        links_raw = await page.evaluate("""
            () => {
                const anchors = document.querySelectorAll('a[href]');
                return Array.from(anchors).map(a => ({
                    href: a.href || '',
                    text: (a.innerText || a.textContent || '').trim().substring(0, 200),
                    is_visible: a.offsetParent !== null
                }));
            }
        """)
        logs.append(LogEntry(level="INFO", message=f"Found {len(links_raw)} links on the page."))

        # --- Extract Cookies ---
        logs.append(LogEntry(level="INFO", message="Extracting browser cookies..."))
        cookies_raw = await context.cookies()
        logs.append(LogEntry(level="INFO", message=f"Found {len(cookies_raw)} cookies."))

        # --- Extract Form Data ---
        logs.append(LogEntry(level="INFO", message="Analyzing form structures..."))
        raw_forms = await page.evaluate("""
            () => {
                const forms = document.querySelectorAll('form');
                return Array.from(forms).map(f => ({
                    action: f.action || '',
                    method: (f.method || 'GET').toUpperCase(),
                    inputs: Array.from(f.querySelectorAll('input')).map(i => ({
                        type: (i.type || 'text').toLowerCase(),
                        name: i.name || ''
                    }))
                }));
            }
        """)

        form_list = []
        suspicious_count = 0

        for raw in raw_forms:
            fi = FormInfo()
            fi.action = raw.get("action", "")
            fi.method = raw.get("method", "GET")

            input_types = [inp.get("type", "text") for inp in raw.get("inputs", [])]
            fi.input_types = input_types
            fi.has_password_field = "password" in input_types
            fi.has_email_field = "email" in input_types

            # Check if form action redirects to external domain
            if fi.action:
                try:
                    action_parsed = urlparse(fi.action)
                    action_host = action_parsed.hostname or ""
                    if action_host and action_host != page_domain:
                        fi.redirects_external = True
                        fi.external_domain = action_host
                        suspicious_count += 1
                except Exception:
                    pass

            form_list.append(fi)

        forms_result.forms = form_list
        forms_result.total_forms = len(form_list)
        forms_result.suspicious_forms = suspicious_count

        if suspicious_count > 0:
            logs.append(LogEntry(
                level="WARN",
                message=f"Found {suspicious_count} form(s) redirecting to external domains!"
            ))

        await browser.close()

    logs.append(LogEntry(level="SUCCESS", message="Browser scan complete."))

    return {
        "page_source": page_source,
        "page_text": page_text,
        "js_contents": js_contents,
        "hidden_elements": hidden_elements,
        "scripts": scripts_info,
        "forms": forms_result,
        "download": download_result,
        "final_url": final_url,
        "page_domain": page_domain,
        "screenshot_b64": screenshot_b64,
        "cookies": cookies_raw,
        "links": links_raw,
        "response_headers": response_headers,
    }

