"""
WHOIS & Domain Analyzer.
Checks domain age, registrar, and detects typosquatting attempts
against well-known brands.
"""
import whois
from datetime import datetime, timezone
from urllib.parse import urlparse
from difflib import SequenceMatcher
from models.schemas import DomainInfo
import unicodedata

import csv
from pathlib import Path

# Load popular brands dataset for typosquatting detection.
# A full Threat Intelligence service could replace this with an external API.
POPULAR_BRANDS = []

def load_popular_brands():
    global POPULAR_BRANDS
    if POPULAR_BRANDS:
        return
    
    csv_path = Path(__file__).parent.parent / "data" / "popular_brands.csv"
    try:
        with open(csv_path, mode='r', encoding='utf-8') as f:
            reader = csv.reader(f)
            next(reader, None)  # Skip header
            for row in reader:
                if row and len(row) > 0:
                    brand = row[0].strip()
                    if brand:
                        POPULAR_BRANDS.append(brand)
    except Exception as e:
        print(f"Uyarı: popular_brands.csv yüklenemedi: {e}")
        # Dosya yoksa veya hata çıkarsa küçük bir acil durum listesi kullan
        POPULAR_BRANDS = ["google", "facebook", "amazon", "apple", "microsoft"]

# Load them immediately when the module is imported
load_popular_brands()


def _extract_domain_name(url: str) -> str:
    """Extract the base domain name (without TLD) from a URL."""
    parsed = urlparse(url)
    hostname = parsed.hostname or ""
    # Remove www. prefix
    if hostname.startswith("www."):
        hostname = hostname[4:]
    # Get just the domain name (before first dot)
    parts = hostname.split(".")
    if len(parts) >= 2:
        return parts[-2]  # e.g. "google" from "mail.google.com"
    return hostname


def normalize_leet(name: str) -> str:
    """Normalize leetspeak and homoglyphs to standard characters."""
    # Convert unicode to ascii where possible (e.g., cyrillic 'a' to latin 'a')
    name = unicodedata.normalize('NFKD', name).encode('ascii', 'ignore').decode('utf-8')
    
    subs = {
        '0': 'o', '1': 'i', '3': 'e', '4': 'a', '5': 's', '7': 't', 
        '@': 'a', '!': 'i', '8': 'b', '9': 'g', 'q': 'g'
    }
    return ''.join(subs.get(ch, ch) for ch in name.lower())


def _check_typosquatting(domain_name: str) -> tuple[bool, str | None]:
    """
    Compare the domain name against popular brands using string
    similarity and homograph detection. A high similarity (>= 0.75) 
    but not exact match indicates potential typosquatting.
    """
    domain_lower = domain_name.lower()
    norm_domain = normalize_leet(domain_lower)

    # Pass 1: Check for exact match first (prevents "google" matching "9to5google" before "google")
    if domain_lower in POPULAR_BRANDS or norm_domain in POPULAR_BRANDS:
        return False, None

    # Pass 2: Check for typosquatting similarity using normalized domain
    for brand in POPULAR_BRANDS:
        ratio = SequenceMatcher(None, norm_domain, brand).ratio()
        if ratio >= 0.75:
            return True, brand

    return False, None


def analyze_domain(url: str) -> DomainInfo:
    """
    Perform WHOIS lookup and typosquatting detection on the target URL.
    """
    result = DomainInfo()

    try:
        parsed = urlparse(url)
        hostname = parsed.hostname or ""
        if hostname.startswith("www."):
            hostname = hostname[4:]
        result.domain = hostname

        # Typosquatting check (doesn't require WHOIS)
        domain_name = _extract_domain_name(url)
        is_typo, target_brand = _check_typosquatting(domain_name)
        result.is_typosquatting = is_typo
        result.typosquatting_target = target_brand

        # WHOIS lookup
        try:
            w = whois.whois(hostname)

            if w.registrar:
                registrar_str = str(w.registrar)
                result.registrar = registrar_str
                # Check for privacy/proxy registrars
                privacy_keywords = ["privacy", "proxy", "whoisguard", "protect", "hidden", "redacted", "statutory", "domains by proxy"]
                reg_lower = registrar_str.lower()
                if any(kw in reg_lower for kw in privacy_keywords):
                    result.registrar_suspicious = True

            creation = w.creation_date
            if isinstance(creation, list):
                creation = creation[0]
                
            expiration = w.expiration_date
            if isinstance(expiration, list):
                expiration = expiration[0]

            if creation:
                if isinstance(creation, datetime):
                    result.creation_date = creation.strftime("%Y-%m-%d")
                    age = datetime.now(timezone.utc) - creation.replace(tzinfo=timezone.utc)
                    result.age_days = age.days
                    
                    # Age score calculation (0 to 100, 100 is best)
                    result.age_score = min((result.age_days / 365) * 100, 100.0)
                    
                    # Domains less than 365 days old (1 year) are suspicious
                    if age.days < 365:
                        result.is_new_domain = True
                else:
                    result.creation_date = str(creation)
            
            if expiration and isinstance(expiration, datetime):
                days_to_expire = (expiration.replace(tzinfo=timezone.utc) - datetime.now(timezone.utc)).days
                if 0 <= days_to_expire < 30:
                    result.is_expiration_near = True

        except Exception as e:
            result.error = f"WHOIS lookup failed: {type(e).__name__}: {e}"

    except Exception as e:
        result.error = f"Domain analysis error: {type(e).__name__}: {e}"

    return result
