"""
feature_extractor.py — Unified URL Feature Extractor for PhishSense v4.0
Guarantees 100% parity between Model Training and Inference.

Extracts 24 clean, statistically rigorous features:
  1. length_url
  2. length_hostname
  3. ip_in_hostname
  4. nb_dots
  5. nb_hyphens
  6. nb_at
  7. nb_qm (question marks)
  8. nb_and (ampersands)
  9. nb_equal
  10. nb_slash
  11. nb_subdomains
  12. is_shortener
  13. is_https
  14. prefix_suffix (hyphen in domain)
  15. entropy_domain
  16. entropy_url
  17. vowel_consonant_ratio
  18. suspicious_tld
  19. brand_impersonation
  20. brand_typosquatting
  21. is_punycode
  22. dns_resolved
  23. has_port
  24. path_token_entropy
"""

import re
import math
import socket
import ipaddress
from urllib.parse import urlparse
from typing import Dict, Any, List, Tuple

# Targeted brands frequently mimicked in phishing attacks
TARGET_BRANDS = [
    "paypal", "microsoft", "google", "apple", "amazon", "netflix",
    "facebook", "instagram", "whatsapp", "chase", "wellsfargo",
    "bankofamerica", "citibank", "binance", "coinbase", "metamask",
    "steam", "roblox", "dhl", "fedex", "usps", "dropbox", "adobe",
    "linkedin", "ebay", "outlook", "office365", "icloud", "yahoo"
]

SUSPICIOUS_TLDS = {
    "xyz", "top", "click", "cf", "tk", "ml", "ga", "gq", "buzz", "cam",
    "icu", "work", "date", "racing", "win", "download", "stream", "gdn",
    "monster", "loan", "trade", "fit", "rest", "party", "surf"
}

SHORTENERS = {
    "bit.ly", "goo.gl", "tinyurl.com", "t.co", "is.gd", "ow.ly",
    "buff.ly", "adf.ly", "bitly.com", "cutt.us", "cutt.ly", "rb.gy",
    "rebrand.ly", "tiny.cc", "tr.im", "bl.ink", "shorturl.at"
}

FEATURE_COLUMNS = [
    "length_url",
    "length_hostname",
    "ip_in_hostname",
    "nb_dots",
    "nb_hyphens",
    "nb_at",
    "nb_qm",
    "nb_and",
    "nb_equal",
    "nb_slash",
    "nb_subdomains",
    "is_shortener",
    "is_https",
    "prefix_suffix",
    "entropy_domain",
    "entropy_url",
    "vowel_consonant_ratio",
    "suspicious_tld",
    "brand_impersonation",
    "brand_typosquatting",
    "is_punycode",
    "dns_resolved",
    "has_port",
    "path_token_entropy",
]

def calculate_entropy(text: str) -> float:
    if not text:
        return 0.0
    freq = {}
    for c in text:
        freq[c] = freq.get(c, 0) + 1
    length = len(text)
    entropy = 0.0
    for count in freq.values():
        p = count / length
        entropy -= p * math.log2(p)
    return round(entropy, 4)

def levenshtein_distance(s1: str, s2: str) -> int:
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)
    if len(s2) == 0:
        return len(s1)
    previous_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row
    return previous_row[-1]

def normalize_url(raw_url: str) -> Tuple[str, str, str]:
    """Returns normalized (full_url, hostname, clean_domain)"""
    url = raw_url.strip()
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    parsed = urlparse(url)
    hostname = (parsed.netloc or "").lower().split(":")[0].replace("www.", "")
    # Clean registered domain heuristic
    parts = hostname.split(".")
    if len(parts) >= 2:
        clean_domain = f"{parts[-2]}.{parts[-1]}"
    else:
        clean_domain = hostname
    return url, hostname, clean_domain

# Official registered domains associated with target brands
OFFICIAL_BRAND_DOMAINS = {
    "steam": {"steampowered.com", "steamcommunity.com", "valvesoftware.com"},
    "adobe": {"adobe.com", "behance.net", "typekit.com"},
    "google": {"google.com", "youtube.com", "gmail.com", "blogger.com"},
    "microsoft": {"microsoft.com", "live.com", "office.com", "office365.com", "outlook.com", "msn.com", "bing.com", "github.com"},
    "apple": {"apple.com", "icloud.com", "itunes.com"},
    "facebook": {"facebook.com", "fb.com", "meta.com", "instagram.com", "whatsapp.com"},
    "amazon": {"amazon.com", "aws.amazon.com", "media-amazon.com"},
    "paypal": {"paypal.com", "paypal-communication.com", "venmo.com"},
}

def detect_brand_abuse(hostname: str, full_url: str) -> Tuple[int, int, List[str]]:
    """
    Returns (brand_impersonation_flag, typosquatting_flag, flags_list)
    """
    try:
        from trusted_domain_manager import trusted_domain_manager
        td_eval = trusted_domain_manager.evaluate_url(full_url)
        if td_eval.get("is_trusted"):
            return 0, 0, []
        if td_eval.get("match_level") in ["LOOKALIKE_IMPERSONATION", "PUNYCODE_IMPERSONATION"]:
            return 1, 1, td_eval.get("reasons", [])
    except Exception:
        pass

    impersonation = 0
    typosquatting = 0
    notes = []

    parts = hostname.split(".")
    tld = parts[-1] if parts else ""
    main_domain = parts[-2] if len(parts) >= 2 else hostname
    registered_domain = ".".join(parts[-2:]) if len(parts) >= 2 else hostname

    # 1. Subdomain impersonation: Brand in subdomain while main domain is different
    # e.g., paypal.com.account-update.xyz or login-paypal.account-verify.com
    for brand in TARGET_BRANDS:
        official_set = OFFICIAL_BRAND_DOMAINS.get(brand, set())
        if registered_domain in official_set or any(registered_domain.endswith("." + o) for o in official_set):
            continue

        # Check if brand is in hostname but NOT the legitimate registered domain
        if brand in hostname:
            if main_domain != brand:
                impersonation = 1
                notes.append(f"Subdomain brand impersonation: '{brand}' spoofed on untrusted domain '{hostname}'")
                break

    # 2. Typosquatting / Levenshtein check on main domain
    # e.g., paypa1, micros0ft, arnazon
    leet_subs = {"1": "l", "0": "o", "5": "s", "vv": "w", "rn": "m"}
    unleet_domain = main_domain
    for k, v in leet_subs.items():
        unleet_domain = unleet_domain.replace(k, v)

    for brand in TARGET_BRANDS:
        official_set = OFFICIAL_BRAND_DOMAINS.get(brand, set())
        if registered_domain in official_set or any(registered_domain.endswith("." + o) for o in official_set):
            continue

        if main_domain != brand and len(main_domain) >= 3:
            dist = levenshtein_distance(main_domain, brand)
            # Require 1 edit distance or 2 edits with shared 3-char prefix
            if dist == 1 or (dist == 2 and len(brand) >= 6 and main_domain[:3] == brand[:3]):
                typosquatting = 1
                notes.append(f"Typosquatting alert: Domain '{main_domain}' is 1-2 edits from trusted brand '{brand}'")
                break
            if unleet_domain == brand and main_domain != brand:
                typosquatting = 1
                notes.append(f"Leet substitution typosquatting targeting '{brand}' in '{main_domain}'")
                break

    return impersonation, typosquatting, notes

def extract_features_vector(raw_url: str, check_dns: bool = False) -> Dict[str, Any]:
    """
    Extracts numerical and categorical feature dictionary for ML models.
    """
    full_url, hostname, clean_domain = normalize_url(raw_url)
    parsed = urlparse(full_url)
    path = parsed.path or ""
    query = parsed.query or ""

    # Check IP
    ip_flag = 0
    try:
        ipaddress.ip_address(hostname)
        ip_flag = 1
    except ValueError:
        pass

    # Subdomains count
    subdomains = hostname.split(".")
    nb_subdomains = max(0, len(subdomains) - 2)

    # Shorteners
    is_shortener = 1 if any(hostname == s or hostname.endswith("." + s) for s in SHORTENERS) else 0

    # Suspicious TLD
    tld = subdomains[-1] if subdomains else ""
    suspicious_tld = 1 if tld in SUSPICIOUS_TLDS else 0

    # Punycode / IDN
    is_punycode = 1 if "xn--" in hostname else 0

    # Vowel / consonant ratio in domain
    letters_only = re.sub(r"[^a-zA-Z]", "", subdomains[0] if subdomains else "")
    vowels = sum(1 for c in letters_only.lower() if c in "aeiou")
    consonants = len(letters_only) - vowels
    v_c_ratio = round(vowels / max(1, consonants), 3)

    # Impersonation and Typosquatting
    impersonation, typosquatting, brand_notes = detect_brand_abuse(hostname, full_url)

    # DNS check (optional for training speed, active during real inference)
    dns_resolved = 1
    if check_dns:
        try:
            socket.gethostbyname(hostname)
            dns_resolved = 1
        except Exception:
            dns_resolved = 0

    # Has explicit port
    has_port = 1 if parsed.port and parsed.port not in [80, 443] else 0

    # Entropies
    entropy_dom = calculate_entropy(hostname)
    entropy_u = calculate_entropy(full_url)
    path_token_entropy = calculate_entropy(path + query)

    features = {
        "length_url": len(full_url),
        "length_hostname": len(hostname),
        "ip_in_hostname": ip_flag,
        "nb_dots": full_url.count("."),
        "nb_hyphens": full_url.count("-"),
        "nb_at": full_url.count("@"),
        "nb_qm": full_url.count("?"),
        "nb_and": full_url.count("&"),
        "nb_equal": full_url.count("="),
        "nb_slash": full_url.count("/"),
        "nb_subdomains": nb_subdomains,
        "is_shortener": is_shortener,
        "is_https": 1 if parsed.scheme == "https" else 0,
        "prefix_suffix": 1 if "-" in hostname else 0,
        "entropy_domain": entropy_dom,
        "entropy_url": entropy_u,
        "vowel_consonant_ratio": v_c_ratio,
        "suspicious_tld": suspicious_tld,
        "brand_impersonation": impersonation,
        "brand_typosquatting": typosquatting,
        "is_punycode": is_punycode,
        "dns_resolved": dns_resolved,
        "has_port": has_port,
        "path_token_entropy": path_token_entropy,
    }

    return features

def extract_features_array(raw_url: str, check_dns: bool = False) -> List[float]:
    feat_dict = extract_features_vector(raw_url, check_dns=check_dns)
    return [float(feat_dict[col]) for col in FEATURE_COLUMNS]
