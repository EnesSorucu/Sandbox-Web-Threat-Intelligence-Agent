"""
Content Analyzer.
Analyzes the page's JS code for obfuscation indicators and
scans the DOM for hidden elements that could mask malicious forms/links.
"""
import re
from models.schemas import ContentAnalysis


# TODO: Mavi Problem - Bu zararlı kod (obfuscation) anahtar kelime listesi yapmacık/kısıtlı bir veri setidir.
# Gerçek bir sistemde YARA kuralları veya daha gelişmiş statik kod analiz (SAST) veri tabanları kullanılmalıdır.
OBFUSCATION_KEYWORDS = [
    "eval(",
    "unescape(",
    "document.write(",
    "String.fromCharCode(",
    "atob(",
    "btoa(",
    "decodeURIComponent(",
    "\\x",  # hex escape sequences
]

# Regex for heavy Base64 blocks (long strings of Base64 chars)
BASE64_PATTERN = re.compile(r'[A-Za-z0-9+/=]{100,}')


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

    for keyword in OBFUSCATION_KEYWORDS:
        if keyword.lower() in all_js.lower():
            found_keywords.add(keyword)

    # Check for heavy base64 blocks
    base64_matches = BASE64_PATTERN.findall(all_js)
    if len(base64_matches) > 2:
        found_keywords.add("Heavy Base64 blocks")

    result.obfuscation_keywords_found = list(found_keywords)
    result.obfuscation_score = min(len(found_keywords) * 20, 100)

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
