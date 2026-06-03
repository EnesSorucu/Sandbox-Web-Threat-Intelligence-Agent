"""
Link Tree / Spider Analyzer.
Extracts all links from the page and classifies them by risk level.
"""
from urllib.parse import urlparse


def analyze_links(links: list[dict], page_domain: str) -> dict:
    """
    Analyze all links found on the page.

    Args:
        links: list of dicts with keys: href, text, is_visible
        page_domain: the domain of the analyzed page

    Returns:
        dict with:
        - total_links: int
        - internal_links: int
        - external_links: int
        - download_links: list of links pointing to dangerous file types
        - insecure_links: list of http:// links (non-HTTPS)
        - suspicious_links: list of links with mismatched text vs href
        - external_domains: list of unique external domains
    """
    DANGEROUS_EXTENSIONS = [
        ".exe", ".msi", ".bat", ".cmd", ".ps1", ".vbs", ".js",
        ".scr", ".pif", ".com", ".apk", ".dmg", ".pkg",
        ".zip", ".rar", ".7z", ".tar", ".gz",
    ]

    internal = 0
    external = 0
    download_links = []
    insecure_links = []
    suspicious_links = []
    external_domains = set()

    for link in links:
        href = link.get("href", "").strip()
        text = link.get("text", "").strip()

        if not href or href.startswith("#") or href.startswith("javascript:") or href.startswith("mailto:"):
            continue

        try:
            parsed = urlparse(href)
        except Exception:
            continue

        link_domain = (parsed.hostname or "").lower()

        # Classify internal vs external
        if link_domain and link_domain != page_domain and not link_domain.endswith("." + page_domain):
            external += 1
            external_domains.add(link_domain)
        else:
            internal += 1

        # Check for dangerous download links
        path_lower = (parsed.path or "").lower()
        for ext in DANGEROUS_EXTENSIONS:
            if path_lower.endswith(ext):
                download_links.append({
                    "href": href[:200],
                    "text": text[:100],
                    "extension": ext,
                })
                break

        # Check for insecure (http://) links
        if parsed.scheme == "http" and link_domain:
            insecure_links.append({
                "href": href[:200],
                "text": text[:100],
            })

        # Check for misleading links (text says one domain, href goes to another)
        if text and link_domain:
            # If the visible text looks like a URL but points somewhere else
            text_lower = text.lower().strip()
            if ("http://" in text_lower or "https://" in text_lower or "www." in text_lower):
                try:
                    text_parsed = urlparse(text_lower if "://" in text_lower else "http://" + text_lower)
                    text_domain = (text_parsed.hostname or "").lower()
                    if text_domain and text_domain != link_domain:
                        suspicious_links.append({
                            "displayed_text": text[:100],
                            "actual_href": href[:200],
                            "text_domain": text_domain,
                            "actual_domain": link_domain,
                        })
                except Exception:
                    pass

    return {
        "total_links": internal + external,
        "internal_links": internal,
        "external_links": external,
        "download_links": download_links[:10],
        "insecure_links": insecure_links[:10],
        "suspicious_links": suspicious_links[:10],
        "external_domains": list(external_domains)[:20],
    }
