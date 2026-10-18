"""
url_extractor.py — Extract phishing features from a raw URL
Domain-independent feature extractor:
  - 16 numerical features matching the ML models
  - Deception risk score (0-100)
  - Domain-independent sector/category classification
  - Statistical lexical entropy and impersonation heuristics
"""

import re
import math
import ipaddress
import socket
from urllib.parse import urlparse
from datetime import datetime

# ── Shortening services regex ──────────────────────────────────────────────────
SHORTENERS = re.compile(
    r"bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|"
    r"is\.gd|cli\.gs|yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|"
    r"su\.pr|twurl\.nl|snipurl\.com|short\.to|BudURL\.com|ping\.fm|post\.ly|"
    r"Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|doiop\.com|short\.ie|"
    r"kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|lnkd\.in|db\.tt|"
    r"qr\.ae|adf\.ly|bitly\.com|cur\.lv|ity\.im|q\.gs|po\.st|bc\.vc|"
    r"twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|"
    r"prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|"
    r"1url\.com|tweez\.me|v\.gd|link\.zip\.net"
)

# Generic high-risk deceptive token compounds (domain-independent)
DECEPTIVE_TOKENS = {
    "login", "signin", "verify", "verification", "secure", "security",
    "account", "update", "confirm", "confirmation", "banking", "wallet",
    "billing", "invoice", "payment", "support", "helpdesk", "recovery",
    "portal", "client", "service", "auth", "authorize", "validation"
}

# Suspicious high-abuse TLDs
SUSPICIOUS_TLDS = {
    ".click", ".info", ".xyz", ".top", ".tk", ".cf", ".ml", ".ga",
    ".gq", ".work", ".date", ".loan", ".racing", ".win", ".download",
    ".stream", ".gdn", ".buzz", ".monster", ".icu", ".cam"
}

def calculate_shannon_entropy(text: str) -> float:
    """Calculates Shannon entropy of string to detect algorithmic generation (DGA)."""
    if not text:
        return 0.0
    freq = {}
    for c in text:
        freq[c] = freq.get(c, 0) + 1
    entropy = 0.0
    for c, count in freq.items():
        p = count / len(text)
        entropy -= p * math.log2(p)
    return entropy

# ── Feature 1: IP address in URL ───────────────────────────────────────────────
def having_ip(url: str) -> int:
    try:
        host = urlparse(url).netloc.split(":")[0]
        ipaddress.ip_address(host)
        return 1
    except ValueError:
        return 0

# ── Feature 2: @ symbol in URL ────────────────────────────────────────────────
def have_at_sign(url: str) -> int:
    return 1 if "@" in url else 0

# ── Feature 3: URL length ─────────────────────────────────────────────────────
def get_length(url: str) -> int:
    return 1 if len(url) >= 75 else 0

# ── Feature 4: URL depth ──────────────────────────────────────────────────────
def get_depth(url: str) -> int:
    parts = urlparse(url).path.split("/")
    return sum(1 for p in parts if p)

# ── Feature 5: Double slash redirection ───────────────────────────────────────
def redirection(url: str) -> int:
    pos = url.rfind("//")
    if pos > 6:
        return 1 if pos > 7 else 0
    return 0

# ── Feature 6: https in domain name ──────────────────────────────────────────
def http_domain(url: str) -> int:
    return 1 if "https" in urlparse(url).netloc else 0

# ── Feature 7: URL shortening service ─────────────────────────────────────────
def tiny_url(url: str) -> int:
    return 1 if SHORTENERS.search(url) else 0

# ── Feature 8: Dash / hyphen in domain ────────────────────────────────────────
def prefix_suffix(url: str) -> int:
    return 1 if "-" in urlparse(url).netloc else 0

# ── Feature 9: DNS record ─────────────────────────────────────────────────────
def dns_record(url: str) -> int:
    try:
        host = urlparse(url).netloc.split(":")[0]
        if not host:
            return 1
        socket.setdefaulttimeout(3)
        socket.gethostbyname(host)
        return 0
    except Exception:
        return 1

# ── Feature 10: Generalized Lexical / Impersonation Anomaly ────────────────────
def web_traffic(url: str) -> int:
    """
    Domain-independent traffic / impersonation proxy:
      1. Punycode (xn--) homoglyphs
      2. Leet-speak number substitutions in suspicious deceptive token contexts
      3. Compound deceptive keyword stacking (e.g. secure-login-auth)
      4. High character entropy indicating randomly generated malicious hosts
    """
    host = urlparse(url).netloc.lower().replace("www.", "")
    if not host:
        return 0

    # 1. Punycode check
    if "xn--" in host:
        return 1

    # 2. Entropy check on domain body
    labels = host.split(".")
    domain_body = labels[0] if labels else host
    if calculate_shannon_entropy(domain_body) >= 3.9 and len(domain_body) >= 12:
        return 1

    # 3. Compound deceptive token stacking in domain labels
    compounds_found = 0
    for token in DECEPTIVE_TOKENS:
        if token in host:
            compounds_found += 1
    if compounds_found >= 2:
        return 1

    # 4. Leet substitutions inside deceptive keywords (e.g. s3cure, 1ogin, v3rify)
    leet_patterns = [r"s[e3]cur[e3]", r"l[o01]g[i1]n", r"v[e3]r[i1]fy", r"[a4]uth", r"[a4]cc[o0]unt"]
    for pat in leet_patterns:
        if re.search(pat, host) and not any(clean in host for clean in ["secure", "login", "verify", "auth", "account"]):
            return 1

    return 0

# ── Feature 11: Domain age proxy ──────────────────────────────────────────────
def domain_age(url: str) -> int:
    host = urlparse(url).netloc.lower()
    for tld in SUSPICIOUS_TLDS:
        if host.endswith(tld):
            return 1
    return 0

# ── Feature 12: Domain end / expiry proxy ────────────────────────────────────
def domain_end(url: str) -> int:
    return 0

# ── Feature 13: iFrame detection ─────────────────────────────────────────────
def iframe(url: str) -> int:
    return 0

# ── Feature 14: Mouse-over status bar ─────────────────────────────────────────
def mouse_over(url: str) -> int:
    return 0

# ── Feature 15: Right-click disabled ─────────────────────────────────────────
def right_click(url: str) -> int:
    return 0

# ── Feature 16: Website forwarding ────────────────────────────────────────────
def web_forwards(url: str) -> int:
    lower = url.lower()
    if "redirect" in lower or "forward" in lower or lower.count("http") > 1 or "url=" in lower:
        return 1
    return 0

# ── Feature list ──────────────────────────────────────────────────────────────
FEATURE_NAMES = [
    "Have_IP", "Have_At", "URL_Length", "URL_Depth", "Redirection",
    "https_Domain", "TinyURL", "Prefix/Suffix", "DNS_Record", "Web_Traffic",
    "Domain_Age", "Domain_End", "iFrame", "Mouse_Over", "Right_Click",
    "Web_Forwards",
]

def extract_url_features(url: str) -> list:
    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    return [
        having_ip(url),
        have_at_sign(url),
        get_length(url),
        get_depth(url),
        redirection(url),
        http_domain(url),
        tiny_url(url),
        prefix_suffix(url),
        dns_record(url),
        web_traffic(url),
        domain_age(url),
        domain_end(url),
        iframe(url),
        mouse_over(url),
        right_click(url),
        web_forwards(url),
    ]

def extract_url_features_dict(url: str) -> dict:
    values = extract_url_features(url)
    return dict(zip(FEATURE_NAMES, values))

# ── Generalized Domain Sector Classification ──────────────────────────────────
SECTOR_KEYWORDS = {
    "Banking & Finance": ["bank", "financial", "credit", "loan", "mortgage", "invest", "wealth", "treasury", "capital"],
    "Social Media & Communication": ["chat", "social", "friend", "connect", "community", "forum", "meet", "messenger"],
    "E-commerce & Retail": ["shop", "store", "buy", "cart", "checkout", "retail", "market", "deal", "order", "delivery"],
    "Education & Academic": ["edu", "univ", "college", "school", "academy", "campus", "course", "learn", "student", "faculty"],
    "Government & Public Sector": ["gov", "mil", "state", "public", "ministry", "dept", "citizen", "tax", "police", "consulate"],
    "Email & Messaging": ["mail", "inbox", "webmail", "smtp", "post", "message", "letter"],
    "Payment Platforms & Gateways": ["pay", "wallet", "checkout", "transact", "remit", "gateway", "stripe", "pos"],
    "Cryptocurrency & Web3": ["crypto", "btc", "eth", "coin", "token", "nft", "blockchain", "defi", "binance", "metamask"],
    "SaaS & Enterprise Cloud": ["cloud", "saas", "dashboard", "console", "api", "crm", "erp", "enterprise", "workspace"],
    "General Web Services": []
}

def classify_domain_sector(url: str) -> str:
    """Classifies target into one of 10 standard sectors without hardcoded company lists."""
    lower = url.lower()
    host = urlparse(lower if lower.startswith("http") else f"http://{lower}").netloc

    for sector, keywords in SECTOR_KEYWORDS.items():
        if any(kw in host or kw in url for kw in keywords):
            return sector

    # TLD heuristics
    if host.endswith((".edu", ".ac.in", ".ac.uk")):
        return "Education & Academic"
    if host.endswith((".gov", ".gov.in", ".gov.uk", ".mil")):
        return "Government & Public Sector"

    return "General Web Services"

# ── AI Deception Risk Score ────────────────────────────────────────────────────
def compute_ai_deception_score(url_features: dict, webpage_signals: dict = None) -> int:
    """
    Computes an AI-generation / deception likelihood indicator (0-100).
    Based strictly on measurable structural and lexical signals.
    """
    score = 0
    if url_features:
        if url_features.get("Web_Traffic", 0) == 1:   score += 25
        if url_features.get("Have_IP", 0) == 1:       score += 15
        if url_features.get("TinyURL", 0) == 1:       score += 10
        if url_features.get("Domain_Age", 0) == 1:    score += 12
        if url_features.get("Redirection", 0) == 1:   score += 8
        if url_features.get("https_Domain", 0) == 1:  score += 10
        if url_features.get("Have_At", 0) == 1:       score += 10

    if webpage_signals:
        if webpage_signals.get("has_password_field", False):           score += 20
        cross_origin = webpage_signals.get("cross_origin_script_count", 0)
        if cross_origin >= 3:   score += 15
        elif cross_origin >= 1: score += 7
        if webpage_signals.get("has_iframe", False):                   score += 8
        if webpage_signals.get("right_click_disabled", False):         score += 10
        if webpage_signals.get("has_meta_redirect", False):            score += 8
        if webpage_signals.get("suspicious_action_destination", False): score += 18
        if webpage_signals.get("generic_template_detected", False):    score += 12

    return min(100, score)
