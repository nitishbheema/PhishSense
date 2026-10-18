"""
trusted_domain_manager.py — PhishSense Production Trusted Domain Knowledge Base v2.0
Strict, Public Suffix List (PSL)-aware domain intelligence layer.

Core Capabilities:
1. Strict PSL-aware root domain extraction via tldextract (no naive split heuristics).
2. Safe URL parsing & RFC 3986 normalization:
   - lowercase hostname, remove default ports (80, 443), strip trailing dots
   - punycode/IDN handling & Cyrillic/Greek Unicode homoglyph confusable normalization
   - separate scheme, hostname, port, path, query, and fragment cleanly
3. Matching Levels:
   - EXACT_OFFICIAL_DOMAIN (+1.0)
   - OFFICIAL_SUBDOMAIN (+0.9)
   - VERIFIED_ALIAS (+0.8)
   - OFFICIAL_REDIRECT (+0.8)
   - MULTI_TENANT_HOSTING (+0.35 - flagged as hosting provider, requires content check)
   - LOOKALIKE_IMPERSONATION (-0.8)
   - PUNYCODE_IMPERSONATION (-0.9)
   - SUSPICIOUS_REDIRECT (-0.7)
   - THREAT_INTELLIGENCE_MATCH (-1.0)
   - UNKNOWN_DOMAIN (0.0)
4. Path / Query / Fragment Dissection:
   - Normal paths (/mail/u/0/, /login, /account, /dashboard, etc.) and fragments (#inbox, #home)
     do NOT penalize legitimate verified domains.
5. Multi-Tenant Hosting Awareness:
   - Platforms like GitHub, AWS, Vercel, Supabase, Firebase are marked `is_hosting_provider=True`.
     Third-party content hosted there is NEVER automatically trusted without scrutiny.
6. Structured, human-readable explanations (never claims "100% safe").
"""

import os
import re
import json
import logging
import idna
from urllib.parse import urlsplit, urlunsplit
from typing import Dict, Any, List, Optional, Tuple

import tldextract

log = logging.getLogger("phishsense-trusted-domains")

# ── Confusable Homoglyph Map (Cyrillic, Greek, lookalikes to Latin) ───────────
HOMOGLYPH_CONFUSABLES = {
    # Cyrillic lookalikes
    '\u0430': 'a', '\u0410': 'A',  # Cyrillic a
    '\u0432': 'b', '\u0412': 'B',  # Cyrillic ve
    '\u0441': 'c', '\u0421': 'C',  # Cyrillic es
    '\u0434': 'd',                 # Cyrillic de
    '\u0435': 'e', '\u0415': 'E',  # Cyrillic ie
    '\u04bb': 'h',                 # Cyrillic shha
    '\u0456': 'i', '\u0406': 'I',  # Cyrillic i
    '\u0458': 'j', '\u0408': 'J',  # Cyrillic je
    '\u043a': 'k', '\u041a': 'K',  # Cyrillic ka
    '\u043c': 'm', '\u041c': 'M',  # Cyrillic em
    '\u043d': 'h',                 # Cyrillic en
    '\u043e': 'o', '\u041e': 'O',  # Cyrillic o
    '\u0440': 'p', '\u0420': 'P',  # Cyrillic er
    '\u0455': 's', '\u0405': 'S',  # Cyrillic dze
    '\u0442': 't', '\u0422': 'T',  # Cyrillic te
    '\u0443': 'y',                 # Cyrillic u
    '\u0445': 'x', '\u0425': 'X',  # Cyrillic ha
    # Greek lookalikes
    '\u03b1': 'a', '\u0391': 'A',  # Greek alpha
    '\u03b2': 'b', '\u0392': 'B',  # Greek beta
    '\u03b5': 'e', '\u0395': 'E',  # Greek epsilon
    '\u03b7': 'n', '\u0397': 'H',  # Greek eta
    '\u03b9': 'i', '\u0399': 'I',  # Greek iota
    '\u03ba': 'k', '\u039a': 'K',  # Greek kappa
    '\u03bf': 'o', '\u039f': 'O',  # Greek omicron
    '\u03c1': 'p', '\u03a1': 'P',  # Greek rho
    '\u03c4': 't', '\u03a4': 'T',  # Greek tau
    '\u03c5': 'u', '\u03a5': 'Y',  # Greek upsilon
    '\u03c7': 'x', '\u03a7': 'X',  # Greek chi
    # Turkish dotless i
    '\u0131': 'i',
}

LEET_REPLACEMENTS = {
    '0': 'o',
    '1': 'l',
    '3': 'e',
    '4': 'a',
    '5': 's',
    '7': 't',
    '8': 'b',
    'vv': 'w',
    'rn': 'm',
}

# Standard benign web navigation paths & fragments that should never be penalized
BENIGN_PATH_TOKENS = {
    "mail", "u", "inbox", "login", "signin", "auth", "account", "dashboard",
    "home", "settings", "profile", "docs", "help", "support", "about",
    "portal", "overview", "billing", "myaccount", "security", "preferences"
}

BENIGN_FRAGMENTS = {
    "inbox", "home", "dashboard", "overview", "settings", "top", "main",
    "profile", "starred", "drafts", "sent", "trash", "spam", "all"
}


def compute_levenshtein(s1: str, s2: str) -> int:
    """Computes exact edit distance between two strings."""
    if len(s1) < len(s2):
        return compute_levenshtein(s2, s1)
    if len(s2) == 0:
        return len(s1)
    prev_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        curr_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = prev_row[j + 1] + 1
            deletions = curr_row[j] + 1
            substitutions = prev_row[j] + (c1 != c2)
            curr_row.append(min(insertions, deletions, substitutions))
        prev_row = curr_row
    return prev_row[-1]


class TrustedDomainManager:
    """
    Manages the Trusted Domain Knowledge Base, PSL normalization,
    homoglyph / punycode lookalike detection, and multi-tenant hosting policies.
    """

    def __init__(self, data_path: Optional[str] = None):
        base_dir = os.path.dirname(__file__)
        self.data_path = data_path or os.path.join(base_dir, "data", "trusted_domains.json")
        self.cache_dir = os.path.join(base_dir, "data", ".tldcache")
        os.makedirs(self.cache_dir, exist_ok=True)

        # Initialize PSL extractor with local cache
        self.psl_extractor = tldextract.TLDExtract(
            cache_dir=self.cache_dir,
            include_psl_private_domains=False
        )

        self.records: List[Dict[str, Any]] = []
        self.domain_to_record: Dict[str, Dict[str, Any]] = {}
        self.alias_to_record: Dict[str, Dict[str, Any]] = {}
        self.brand_to_record: Dict[str, Dict[str, Any]] = {}
        self.metadata: Dict[str, Any] = {}

        self.load_database()

    def load_database(self) -> None:
        """Loads and indexes the trusted domain knowledge base."""
        if not os.path.exists(self.data_path):
            log.warning("Trusted domains database not found at %s", self.data_path)
            return

        try:
            with open(self.data_path, "r", encoding="utf-8") as f:
                data = json.load(f)

            self.metadata = {
                "version": data.get("version", "2.0.0"),
                "last_updated": data.get("last_updated", "unknown"),
                "description": data.get("description", ""),
                "verification_sources": data.get("verification_sources", [])
            }

            self.records = data.get("trusted_domains", [])
            self.domain_to_record.clear()
            self.alias_to_record.clear()
            self.brand_to_record.clear()
            self.subdomain_to_record: Dict[str, Dict[str, Any]] = {}

            for rec in self.records:
                b_name = rec.get("brand_name", "").lower()
                self.brand_to_record[b_name] = rec

                # Index primary registrable domain
                reg_dom = rec.get("registrable_domain", "").lower()
                if reg_dom:
                    self.domain_to_record[reg_dom] = rec

                # Index all official domains
                for o_dom in rec.get("official_domains", []):
                    self.domain_to_record[o_dom.lower()] = rec

                # Index aliases & shorteners
                for alias in rec.get("official_aliases", []):
                    self.alias_to_record[alias.lower()] = rec
                    self.domain_to_record[alias.lower()] = rec

                # Index specific legitimate subdomains
                for sub_pat in rec.get("legitimate_subdomain_patterns", []):
                    if "*" not in sub_pat and "/" not in sub_pat:
                        self.subdomain_to_record[sub_pat.lower()] = rec

            log.info("TrustedDomainManager loaded %d records covering %d unique official domains (Version %s)",
                     len(self.records), len(self.domain_to_record), self.metadata.get("version"))

        except Exception as e:
            log.error("Failed to load trusted domains database: %s", e)

    def reload(self) -> Dict[str, Any]:
        """Hot-reloads the knowledge base from disk."""
        self.load_database()
        return self.get_summary()

    def get_summary(self) -> Dict[str, Any]:
        """Returns knowledge base statistics and metadata."""
        categories = list(set(r.get("category", "Other") for r in self.records))
        return {
            "version": self.metadata.get("version", "2.0.0"),
            "last_updated": self.metadata.get("last_updated"),
            "total_records": len(self.records),
            "indexed_domains_count": len(self.domain_to_record),
            "categories": sorted(categories),
            "verification_sources": self.metadata.get("verification_sources", [])
        }

    def safe_parse_and_normalize(self, raw_url: str) -> Dict[str, Any]:
        """
        Safely parses and normalizes a URL according to RFC 3986 & PSL standards.
        Handles default ports, trailing dots, punycode decoding, and homoglyphs.
        """
        url = raw_url.strip()
        if not url:
            return {"valid": False, "error": "Empty URL"}

        # Ensure scheme is present for parsing
        has_scheme = bool(re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", url))
        if not has_scheme:
            url = "https://" + url

        try:
            parts = urlsplit(url)
        except Exception as e:
            return {"valid": False, "error": f"Invalid URL syntax: {e}"}

        scheme = parts.scheme.lower()
        netloc = parts.netloc.strip()

        # Extract port if explicitly present
        port = None
        hostname = netloc
        if "@" in hostname:
            hostname = hostname.split("@")[-1]

        if ":" in hostname:
            h_parts = hostname.split(":")
            hostname = h_parts[0]
            try:
                port = int(h_parts[1])
            except ValueError:
                port = None

        # Normalize hostname: lowercase, remove trailing dots
        hostname = hostname.lower().rstrip(".")

        # Strip default ports
        if (scheme == "http" and port == 80) or (scheme == "https" and port == 443):
            port = None

        # Check for punycode / IDN
        is_punycode = "xn--" in hostname
        unicode_hostname = hostname
        if is_punycode:
            try:
                unicode_hostname = idna.decode(hostname)
            except Exception:
                unicode_hostname = hostname

        # Detect Unicode homoglyphs
        homoglyph_detected = False
        normalized_ascii_hostname = ""
        for char in unicode_hostname:
            if char in HOMOGLYPH_CONFUSABLES:
                homoglyph_detected = True
                normalized_ascii_hostname += HOMOGLYPH_CONFUSABLES[char]
            else:
                normalized_ascii_hostname += char

        # PSL extraction
        extracted = self.psl_extractor(hostname)
        subdomain = extracted.subdomain.lower()
        domain = extracted.domain.lower()
        suffix = extracted.suffix.lower()

        if domain:
            registrable_domain = f"{domain}.{suffix}" if suffix else domain
        else:
            # Suffix-only hostname e.g. "nic.in", "gov.uk"
            registrable_domain = suffix

        # Reconstructed normalized URL
        norm_netloc = hostname if not port else f"{hostname}:{port}"
        normalized_url = urlunsplit((scheme, norm_netloc, parts.path or "/", parts.query, parts.fragment))

        # Dissect path & fragment
        path = parts.path or "/"
        query = parts.query or ""
        fragment = parts.fragment or ""

        return {
            "valid": True,
            "original_url": raw_url,
            "normalized_url": normalized_url,
            "scheme": scheme,
            "hostname": hostname,
            "unicode_hostname": unicode_hostname,
            "normalized_ascii_hostname": normalized_ascii_hostname,
            "is_punycode": is_punycode,
            "homoglyph_detected": homoglyph_detected,
            "port": port,
            "path": path,
            "query": query,
            "fragment": fragment,
            "subdomain": subdomain,
            "domain_label": domain,
            "public_suffix": suffix,
            "registrable_domain": registrable_domain,
        }

    def check_lookalike_and_impersonation(
        self,
        hostname: str,
        registrable_domain: str,
        subdomain: str,
        normalized_ascii_hostname: str,
        is_punycode: bool,
        homoglyph_detected: bool
    ) -> Optional[Dict[str, Any]]:
        """
        Detects if a domain mimics a verified trusted brand without owning the official domain:
        - Unicode homoglyphs / punycode lookalikes
        - Subdomain brand embedding (e.g. google.login.attacker.com)
        - Levenshtein / typosquatting (e.g. paypa1.com, g00gle.com)
        """
        # If the domain is an authorized official domain in our knowledge base, it cannot be a lookalike
        if not is_punycode and not homoglyph_detected:
            if registrable_domain in self.domain_to_record or hostname in self.domain_to_record:
                return None

        # 1. Punycode / Homoglyph impersonation
        if is_punycode or homoglyph_detected:
            # Check if normalized ASCII maps to any official domain
            norm_extracted = self.psl_extractor(normalized_ascii_hostname)
            norm_reg = f"{norm_extracted.domain}.{norm_extracted.suffix}" if norm_extracted.domain else norm_extracted.suffix
            if norm_reg in self.domain_to_record:
                rec = self.domain_to_record[norm_reg]
                return {
                    "level": "PUNYCODE_IMPERSONATION",
                    "score_modifier": -0.9,
                    "target_brand": rec["brand_name"],
                    "service": rec.get("service_name"),
                    "details": f"Deceptive Punycode/Homoglyph domain mimics official '{rec['brand_name']}' ({norm_reg})"
                }

        # 2. Subdomain brand embedding check
        # e.g. brand is embedded in subdomain but registrable domain belongs to attacker
        sub_tokens = re.split(r"[.\-_]", subdomain) if subdomain else []
        for brand_key, rec in self.brand_to_record.items():
            official_doms = set(rec.get("official_domains", []))
            official_doms.add(rec.get("registrable_domain", ""))

            # If registrable domain is already official, skip
            if registrable_domain in official_doms:
                continue

            brand_simple = re.sub(r"[^a-z0-9]", "", brand_key)
            if not brand_simple or len(brand_simple) < 4:
                continue

            # Check if brand appears in subdomain tokens
            for tok in sub_tokens:
                if tok == brand_simple or tok == f"{brand_simple}-login" or tok == f"login-{brand_simple}":
                    return {
                        "level": "LOOKALIKE_IMPERSONATION",
                        "score_modifier": -0.8,
                        "target_brand": rec["brand_name"],
                        "service": rec.get("service_name"),
                        "details": f"Brand Impersonation: Trusted brand '{rec['brand_name']}' spoofed in subdomain of unverified domain '{registrable_domain}'"
                    }

        # 3. Typosquatting / Levenshtein & Leet substitution on registrable domain
        # e.g. paypa1.com, micros0ft.com, arnazon.com
        ext = self.psl_extractor(hostname)
        main_label = ext.domain.lower()

        # Unleet domain label
        unleet_label = main_label
        for k, v in LEET_REPLACEMENTS.items():
            unleet_label = unleet_label.replace(k, v)

        for brand_key, rec in self.brand_to_record.items():
            official_doms = set(rec.get("official_domains", []))
            official_doms.add(rec.get("registrable_domain", ""))

            if registrable_domain in official_doms:
                continue

            brand_simple = re.sub(r"[^a-z0-9]", "", brand_key)
            if not brand_simple or len(brand_simple) < 4:
                continue

            # Check unleet match
            if unleet_label == brand_simple and main_label != brand_simple:
                return {
                    "level": "LOOKALIKE_IMPERSONATION",
                    "score_modifier": -0.8,
                    "target_brand": rec["brand_name"],
                    "service": rec.get("service_name"),
                    "details": f"Character substitution typosquatting: '{main_label}' mimics trusted '{rec['brand_name']}'"
                }

            # Levenshtein distance 1 or 2
            if len(main_label) >= 4 and abs(len(main_label) - len(brand_simple)) <= 2:
                dist = compute_levenshtein(main_label, brand_simple)
                if dist == 1 or (dist == 2 and main_label[:3] == brand_simple[:3]):
                    return {
                        "level": "LOOKALIKE_IMPERSONATION",
                        "score_modifier": -0.8,
                        "target_brand": rec["brand_name"],
                        "service": rec.get("service_name"),
                        "details": f"Typosquatting variant: Domain '{registrable_domain}' is {dist} edit(s) from '{rec['brand_name']}' ({brand_simple})"
                    }

        return None

    def evaluate_url(
        self,
        raw_url: str,
        threat_match: Optional[Dict[str, Any]] = None,
        redirect_info: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Executes strict, PSL-aware Trusted Domain Intelligence evaluation.
        Returns full analysis dictionary with match level, trust score, and explainable reasons.
        """
        norm = self.safe_parse_and_normalize(raw_url)
        if not norm.get("valid"):
            return {
                "is_trusted": False,
                "match_level": "INVALID_URL",
                "match_score": 0.0,
                "brand_name": None,
                "service_name": None,
                "registrable_domain": "",
                "status": "UNVERIFIED",
                "category": "Unknown",
                "is_hosting_provider": False,
                "reasons": ["Invalid URL syntax or malformed structure"],
                "normalized": norm
            }

        hostname = norm["hostname"]
        reg_domain = norm["registrable_domain"]
        subdomain = norm["subdomain"]
        path = norm["path"]
        fragment = norm["fragment"]

        reasons: List[str] = []

        # ── 1. Threat Intelligence Override Check ─────────────────────────────
        if threat_match and threat_match.get("is_known_threat"):
            return {
                "is_trusted": False,
                "match_level": "THREAT_INTELLIGENCE_MATCH",
                "match_score": -1.0,
                "brand_name": None,
                "service_name": None,
                "registrable_domain": reg_domain,
                "status": "FLAGGED_MALICIOUS",
                "category": "Security Threat",
                "is_hosting_provider": False,
                "reasons": [
                    f"Confirmed threat intelligence record in {threat_match.get('source', 'Threat Feeds')}",
                    "Domain or URL actively documented in phishing/malware feeds",
                    "Immediate block advised"
                ],
                "normalized": norm
            }

        # ── 2. Check for Lookalike / Impersonation / Typosquatting ─────────────
        lookalike = self.check_lookalike_and_impersonation(
            hostname=hostname,
            registrable_domain=reg_domain,
            subdomain=subdomain,
            normalized_ascii_hostname=norm["normalized_ascii_hostname"],
            is_punycode=norm["is_punycode"],
            homoglyph_detected=norm["homoglyph_detected"]
        )

        if lookalike:
            return {
                "is_trusted": False,
                "match_level": lookalike["level"],
                "match_score": lookalike["score_modifier"],
                "brand_name": lookalike["target_brand"],
                "service_name": lookalike.get("service"),
                "registrable_domain": reg_domain,
                "status": "IMPERSONATION_DETECTED",
                "category": "Security Threat",
                "is_hosting_provider": False,
                "reasons": [
                    f"⚠️ {lookalike['details']}",
                    "Domain resembles verified brand but does not belong to authorized corporate infrastructure",
                    "High risk of deceptive credential harvesting or identity spoofing"
                ],
                "normalized": norm
            }

        # ── 3. Check Exact, Subdomain, or Alias Match in Knowledge Base ───────
        rec = None
        match_level = "UNKNOWN_DOMAIN"
        match_score = 0.0

        # Check if registrable domain is in knowledge base
        if reg_domain in self.domain_to_record:
            rec = self.domain_to_record[reg_domain]
            if hostname == reg_domain:
                match_level = "EXACT_OFFICIAL_DOMAIN"
                match_score = 1.0
            elif subdomain:
                # Subdomain under official registrable domain
                match_level = "OFFICIAL_SUBDOMAIN"
                match_score = 0.9
            elif hostname in rec.get("official_aliases", []):
                match_level = "VERIFIED_ALIAS"
                match_score = 0.8
            else:
                match_level = "EXACT_OFFICIAL_DOMAIN"
                match_score = 1.0
        # Exact match on hostname in domain_to_record or alias_to_record
        elif hostname in self.domain_to_record:
            rec = self.domain_to_record[hostname]
            if hostname in self.alias_to_record:
                match_level = "VERIFIED_ALIAS"
                match_score = 0.8
            else:
                match_level = "EXACT_OFFICIAL_DOMAIN"
                match_score = 1.0

        # ── 4. Evaluate Multi-Tenant Hosting Providers ────────────────────────
        if rec and rec.get("is_hosting_provider"):
            # Multi-tenant providers host user-controlled repositories/apps (e.g. GitHub, AWS, Vercel, Supabase)
            match_level = "MULTI_TENANT_HOSTING"
            match_score = 0.35
            is_trusted = True
            brand_name = rec["brand_name"]
            service_name = rec.get("service_name", brand_name)
            category = rec.get("category", "Cloud")

            reasons.append(f"✓ Verified infrastructure provider: {brand_name}")
            reasons.append("⚠️ Multi-tenant hosting platform: user-uploaded content requires continuous inspection")
            reasons.append("✓ Hostname matches registered provider infrastructure")

            # Check path and query
            reasons.append("✓ No domain-level impersonation detected")
            if not threat_match or not threat_match.get("is_known_threat"):
                reasons.append("✓ No known threat detected on exact resource path")

            return {
                "is_trusted": is_trusted,
                "match_level": match_level,
                "match_score": match_score,
                "brand_name": brand_name,
                "service_name": service_name,
                "registrable_domain": reg_domain,
                "status": "MONITORED_HOSTING",
                "category": category,
                "is_hosting_provider": True,
                "reasons": reasons,
                "normalized": norm
            }

        # ── 5. Official Verified Domain or Subdomain ──────────────────────────
        if rec:
            brand_name = rec["brand_name"]
            service_name = rec.get("service_name", brand_name)
            category = rec.get("category", "Technology")

            # Check if this specific subdomain maps to a known dedicated service (e.g. mail.google.com -> Gmail)
            if hostname in self.subdomain_to_record:
                sub_rec = self.subdomain_to_record[hostname]
                brand_name = sub_rec.get("brand_name", brand_name)
                service_name = sub_rec.get("service_name", service_name)
                category = sub_rec.get("category", category)

            # Check for official redirect relationship
            if redirect_info and redirect_info.get("redirect_count", 0) > 0:
                final_url = redirect_info.get("final_url", "")
                final_norm = self.safe_parse_and_normalize(final_url)
                final_reg = final_norm.get("registrable_domain", "")
                if final_reg in rec.get("official_domains", []) or final_reg == rec.get("registrable_domain"):
                    match_level = "OFFICIAL_REDIRECT"
                    match_score = 0.8
                    reasons.append(f"✓ Official {brand_name} service redirect to verified destination")

            # Construct structured explainable reasons (as requested in Section 8)
            reasons.append(f"✓ Official {brand_name} domain ({reg_domain})")
            if match_level == "OFFICIAL_SUBDOMAIN":
                reasons.append(f"✓ Valid {service_name} subdomain ({hostname})")
            elif match_level == "VERIFIED_ALIAS":
                reasons.append(f"✓ Verified official alias for {brand_name} ({hostname})")
            else:
                reasons.append(f"✓ Exact verified root domain for {brand_name}")

            reasons.append("✓ No suspicious domain impersonation")

            # Path & Fragment verification (Section 3)
            # Normal paths and fragments must not increase risk
            clean_path = path.strip("/")
            path_segments = [p.lower() for p in clean_path.split("/") if p]
            if not path_segments:
                reasons.append("✓ Normal root path")
            elif any(seg in BENIGN_PATH_TOKENS for seg in path_segments):
                reasons.append(f"✓ Normal URL path: /{clean_path} is standard application routing")
            else:
                reasons.append(f"✓ Normal URL path: {path}")

            if fragment:
                frag_clean = fragment.lstrip("#").lower()
                if frag_clean in BENIGN_FRAGMENTS:
                    reasons.append(f"✓ URL fragment does not indicate phishing: #{frag_clean} is standard navigation")
                else:
                    reasons.append(f"✓ URL fragment does not indicate phishing: #{frag_clean}")

            reasons.append("✓ No known threat detected")

            return {
                "is_trusted": True,
                "match_level": match_level,
                "match_score": match_score,
                "brand_name": brand_name,
                "service_name": service_name,
                "registrable_domain": reg_domain,
                "status": "VERIFIED",
                "category": category,
                "is_hosting_provider": False,
                "reasons": reasons,
                "normalized": norm
            }

        # ── 6. Unmatched Domain (Neutral / Unknown) ───────────────────────────
        # Not in trusted knowledge base, but also not an obvious lookalike
        reasons.append("Domain not listed in official trusted knowledge base")
        reasons.append("Evaluated under standard calibrated machine learning and live analysis pipeline")
        if not threat_match or not threat_match.get("is_known_threat"):
            reasons.append("No known threat detected in global intelligence feeds")

        return {
            "is_trusted": False,
            "match_level": "UNKNOWN_DOMAIN",
            "match_score": 0.0,
            "brand_name": None,
            "service_name": None,
            "registrable_domain": reg_domain,
            "status": "UNVERIFIED",
            "category": "Uncategorized",
            "is_hosting_provider": False,
            "reasons": reasons,
            "normalized": norm
        }


# Singleton instance
trusted_domain_manager = TrustedDomainManager()
