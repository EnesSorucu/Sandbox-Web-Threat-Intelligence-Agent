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


import csv
from pathlib import Path

# TODO: Mavi Problem - Şimdilik Majestic Million dataset'inden Top 10k markayı çekiyoruz. 
# Tam teşekküllü bir Threat Intelligence için YARA veya benzeri dış servisler kullanılmalıdır.
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


def _check_typosquatting(domain_name: str) -> tuple[bool, str | None]:
    """
    Compare the domain name against popular brands using string
    similarity. A high similarity (>= 0.75) but not exact match
    indicates potential typosquatting.
    """
    domain_lower = domain_name.lower()

    # Pass 1: Check for exact match first (prevents "google" matching "9to5google" before "google")
    if domain_lower in POPULAR_BRANDS:
        return False, None

    # Pass 2: Check for typosquatting similarity
    for brand in POPULAR_BRANDS:
        ratio = SequenceMatcher(None, domain_lower, brand).ratio()
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
                result.registrar = str(w.registrar)

            creation = w.creation_date
            if isinstance(creation, list):
                creation = creation[0]

            if creation:
                if isinstance(creation, datetime):
                    result.creation_date = creation.strftime("%Y-%m-%d")
                    age = datetime.now(timezone.utc) - creation.replace(tzinfo=timezone.utc)
                    result.age_days = age.days
                    # Domains less than 365 days old (1 year) are suspicious
                    # Phishing and piracy sites frequently rotate domains
                    if age.days < 365:
                        result.is_new_domain = True
                else:
                    result.creation_date = str(creation)

        except Exception as e:
            result.error = f"WHOIS lookup failed: {type(e).__name__}: {e}"

    except Exception as e:
        result.error = f"Domain analysis error: {type(e).__name__}: {e}"

    return result
