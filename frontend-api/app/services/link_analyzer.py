"""
Link Tree / Spider Analyzer.
Extracts all links from the page and classifies them by risk level.
"""
from urllib.parse import urlparse
from app.services.domain_analyzer import POPULAR_BRANDS
import re
import re

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
        - hidden_links: list of links that are not visible to the user
        - external_domains: list of unique external domains
    """
    # Expanded list of dangerous extensions (GTUG Standards)
    DANGEROUS_EXTENSIONS = [
        ".exe", ".msi", ".bat", ".cmd", ".ps1", ".vbs", ".js",
        ".scr", ".pif", ".com", ".apk", ".dmg", ".pkg",
        ".zip", ".rar", ".7z", ".tar", ".gz",
        ".docm", ".xlsm", ".pptm", ".pdf", ".jar", ".sh", ".swf", ".iso"
    ]

    internal = 0
    external = 0
    download_links = []
    insecure_links = []
    suspicious_links = []
    hidden_links = []
    external_domains = set()

    for link in links:  # linkleri temizler
        href = link.get("href", "").strip()
        text = link.get("text", "").strip()
        is_visible = link.get("is_visible", True)

        if not href or href.startswith("#") or href.startswith("javascript:") or href.startswith("mailto:"):
            continue

        try:
            parsed = urlparse(href)
        except Exception:
            continue

        link_domain = (parsed.hostname or "").lower()

        # Check for hidden links
        if not is_visible:
            hidden_links.append({
                "href": href[:200],
                "text": text[:100]
            })

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

        # Check for misleading links (text vs href mismatch) uyuşma kontrolü
        if text and link_domain:
            text_lower = text.lower().strip()
            
            # 1. URL mimicking (Text looks like a URL but points elsewhere)
            if ("http://" in text_lower or "https://" in text_lower or "www." in text_lower):
                try:
                    text_parsed = urlparse(text_lower if "://" in text_lower else "http://" + text_lower)
                    text_domain = (text_parsed.hostname or "").lower()
                    if text_domain and text_domain != link_domain:
                        suspicious_links.append({
                            "displayed_text": text[:100],
                            "actual_href": href[:200],
                            "reason": f"Text domain ({text_domain}) does not match actual domain ({link_domain})",
                            "text_domain": text_domain,
                            "actual_domain": link_domain,
                        })
                        continue  # Move to next link if already flagged
                except Exception:
                    pass

            # 2. Brand mimicking (Text contains a brand name but points to a different domain)
            if link_domain != page_domain and not link_domain.endswith("." + page_domain):
                # Eğer hedef domain zaten popüler/güvenilir bir markaysa (Örn: youtube.com, x.com, wsj.com, barrons.com),
                # bu bir yanıltıcı taklit değildir, meşru bir dış yönlendirmedir.
                dest_is_popular = False
                for pb in POPULAR_BRANDS:
                    if len(pb) >= 4 and pb.lower() in link_domain:
                        dest_is_popular = True
                        break
                
                if not dest_is_popular:
                    # Sadece tam kelimeleri alıyoruz (Örn: "oturum" içindeki "tur" markasını engellemek için)
                    words = set(re.findall(r'\w+', text_lower))
                    for brand in POPULAR_BRANDS:
                        # Marka adının en az 4 harfli olması ve tam bir kelime olarak geçmesi şartı
                        if len(brand) >= 4 and brand.lower() in words and brand.lower() not in link_domain:
                            suspicious_links.append({
                                "displayed_text": text[:100],
                                "actual_href": href[:200],
                                "reason": f"Brand '{brand}' mentioned in text but leads to {link_domain}",
                                "text_domain": brand,
                                "actual_domain": link_domain,
                            })
                            break

    return {
        "total_links": internal + external,
        "internal_links": internal,
        "external_links": external,
        "download_links": download_links[:10],
        "insecure_links": insecure_links[:10],
        "suspicious_links": suspicious_links[:10],
        "hidden_links": hidden_links[:10],
        "external_domains": list(external_domains)[:20],
    }
