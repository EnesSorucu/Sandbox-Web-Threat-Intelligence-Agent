"""
Content Analyzer.
Analyzes the page's JS code for obfuscation indicators and
scans the DOM for hidden elements that could mask malicious forms/links.
"""
import re
from models.schemas import ContentAnalysis


# Defined rules and associated risk weights for JavaScript obfuscation detection.
# In a production system, this should be backed by advanced SAST tools or YARA rules.
OBFUSCATION_RULES = {
    r"eval\(": 40,
    r"unescape\(": 30,
    r"String\.fromCharCode\(": 30,
    r"atob\(": 20,
    r"btoa\(": 20,
    r"decodeURIComponent\(": 10,
    r"\\x[0-9a-fA-F]{2}": 20,  # hex escape sequences
}

# Regex for heavy Base64 blocks (blocks longer than 200 chars)
BASE64_PATTERN = re.compile(r'(?:[A-Za-z0-9+/]{4}){50,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?')

# Regex for document.write false-positive analysis
DOC_WRITE_PATTERN = re.compile(r"document\.write\s*\(\s*(['\"`])(.*?)(\1)\s*\)", re.IGNORECASE)


def analyze_content(
    page_source: str,
    js_contents: list[str],
    hidden_elements: list[dict],
    scripts: list[dict],
    page_domain: str,
) -> ContentAnalysis:
    """
    Analyze page content for:
    1. JS obfuscation indicators
    2. Hidden DOM elements (forms, links)
    3. External script analysis
    """
    result = ContentAnalysis()

    # --- 1. JS Obfuscation Detection ---
    all_js = "\n".join(js_contents) + "\n" + page_source
    found_keywords = set()
    total_score = 0

    # Performans ve Ağırlıklı Puanlama (Regex tabanlı)
    for pattern_str, weight in OBFUSCATION_RULES.items():
        if re.search(pattern_str, all_js, re.IGNORECASE):
            clean_name = pattern_str.replace("\\", "").replace("(", "").replace("[0-9a-fA-F]{2}", "hex")
            found_keywords.add(f"{clean_name} (+{weight})")
            total_score += weight

    # document.write false-positive analizi
    doc_write_matches = DOC_WRITE_PATTERN.findall(all_js)
    if doc_write_matches:
        is_malicious_write = False
        for match in doc_write_matches:
            content = match[1].lower()
            if "<iframe" in content or "<script" in content:
                is_malicious_write = True
                break
        
        if is_malicious_write:
            found_keywords.add("Malicious document.write [iframe/script] (+40)")
            total_score += 40
        else:
            found_keywords.add("Standard document.write (+5)")
            total_score += 5

    # Base64 Kontrolü (Sadece uzun bloklar risktir)
    # data:image, data:font, vb. Base64 medya/font blokları zararsızdır, onları temizle
    # Whitespace/newlines içeren multiline blokları da temizlemek için [^"\'\)]+ kullanıyoruz
    cleaned_js = re.sub(r'data:(?:image|font|audio|video|application/font)[^"\'\)]+', '', all_js)
    base64_matches = BASE64_PATTERN.findall(cleaned_js)
    longest_b64 = max((len(m) for m in base64_matches), default=0)
    
    # Çözücü/deşifre edici fonksiyonlar olmadan tek başına ham base64 bloğu tehlikeli değildir (sadece resim, font veya config verisidir)
    has_decoder = any(any(kw in kw_item for kw in ["eval", "unescape", "fromCharCode", "atob", "btoa"]) for kw_item in found_keywords)

    if longest_b64 > 500 and has_decoder:
        found_keywords.add("Critical Base64 block > 500 chars (+40)")
        total_score += 40
    elif longest_b64 > 200 and has_decoder:
        found_keywords.add("Suspicious Base64 block > 200 chars (+20)")
        total_score += 20

    result.obfuscation_keywords_found = list(found_keywords)
    result.obfuscation_score = min(total_score, 100)

    # --- 2. Hidden Elements Analysis ---
    result.hidden_element_count = len(hidden_elements)
    result.hidden_elements = hidden_elements

    for elem in hidden_elements:
        tag = elem.get("tag", "").lower()
        info = elem.get("info", "")
        if tag == "form":
            result.hidden_forms.append(info)
        elif tag == "a":
            result.hidden_links.append(info)

    # --- 3. External Scripts Ratio ---
    result.total_scripts = len(scripts)
    external = []

    for script in scripts:
        src = script.get("src", "")
        if src and page_domain not in src:
            external.append(src)

    result.external_scripts = external
    if result.total_scripts > 0:
        result.external_script_ratio = round(
            len(external) / result.total_scripts, 2
        )

    return result
