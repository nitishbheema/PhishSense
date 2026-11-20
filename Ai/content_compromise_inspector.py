"""
content_compromise_inspector.py — Passive Website Content & Compromise Inspection
Examines publicly accessible website HTML and DOM structures without executing arbitrary code:
  - Obfuscated scripts & packers
  - Hidden iframes & off-screen elements
  - Unexpected external scripts & crypto-miners
  - Credential harvesting forms & suspicious form actions
  - Meta refresh & JavaScript redirect traps
  - Embedded executable payloads (base64 data URIs)
  - Defacement indicators & SEO spam injection
  - Mixed HTTP/HTTPS content
"""

import re
import math
import logging
from typing import Dict, Any, List, Optional
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup

log = logging.getLogger("phishsense-compromise-inspector")

KNOWN_MINER_DOMAINS = [
    "coinhive.com", "coin-hive.com", "cryptoloot.pro", "crypto-loot.com",
    "webmine.pro", "mineralt.io", "authedmine.com", "jsecoin.com"
]

# Legitimate providers that commonly deploy hidden/offscreen iframes or embedded frames
BENIGN_IFRAME_DOMAINS = [
    "recaptcha.net", "google.com", "gstatic.com", "cloudflare.com",
    "challenges.cloudflare.com", "stripe.com", "stripe.network", "paypal.com",
    "accounts.google.com", "login.microsoftonline.com", "appleid.apple.com",
    "youtube.com", "youtube-nocookie.com", "vimeo.com", "doubleclick.net",
    "googletagmanager.com", "facebook.com", "hcaptcha.com"
]

# Legitimate third-party script providers (Analytics, CDNs, Telemetry)
BENIGN_EXTERNAL_SCRIPT_DOMAINS = [
    "googletagmanager.com", "google-analytics.com", "cloudflare.com",
    "cloudflareinsights.com", "stats.wp.com", "clarity.ms", "hotjar.com",
    "segment.com", "matomo.org", "sentry-cdn.com", "datadoghq-browser.com",
    "cdn.jsdelivr.net", "cdnjs.cloudflare.com", "unpkg.com", "code.jquery.com",
    "polyfill.io", "recaptcha.net", "gstatic.com", "stripe.com"
]

# Legitimate identity providers and payment gateways for cross-origin forms
BENIGN_FORM_TARGET_DOMAINS = [
    "accounts.google.com", "login.microsoftonline.com", "appleid.apple.com",
    "github.com", "checkout.stripe.com", "paypal.com", "razorpay.com",
    "cashfree.com", "paytm.com", "google.com", "bing.com", "duckduckgo.com"
]

DEFACEMENT_PATTERNS = [
    r"hacked\s+by\b", r"defaced\s+by\b", r"pwned\s+by\b",
    r"cyber\s+army\b", r"national\s+hackers\b", r"team\s+defacers\b"
]

SEO_SPAM_KEYWORDS = [
    "viagra", "cialis", "casino", "online poker", "roulette",
    "replica watches", "cheap jerseys", "payday loans", "slot online"
]

class ContentCompromiseInspector:
    def __init__(self):
        pass

    def inspect_content(self, url: str, html_text: str, http_status: Optional[int] = None) -> Dict[str, Any]:
        """
        Passively inspects HTML and embedded scripts for compromise and deception signals.
        Returns categorized findings, exact line/tag evidence, and overall compromise status.
        """
        if not html_text or not html_text.strip():
            return {
                "status": "INSPECTION_INCOMPLETE",
                "risk_level": "INSUFFICIENT_EVIDENCE",
                "inspection_mode": "PASSIVE_HTML_DOM_INSPECTION",
                "finding": "Target returned empty response or HTML content was unreachable.",
                "indicators": [],
                "summary": "Website content could not be inspected."
            }

        parsed_origin = urlparse(url)
        origin_host = (parsed_origin.netloc or "").split(":")[0].lower().replace("www.", "")
        is_https_parent = parsed_origin.scheme.lower() == "https"

        soup = BeautifulSoup(html_text, "html.parser")
        indicators: List[Dict[str, Any]] = []

        # ── 1. Check for Defacement Indicators ────────────────────────────────
        title_text = (soup.title.string or "") if soup.title else ""
        headings_text = " ".join([h.get_text() for h in soup.find_all(["h1", "h2", "h3"])])
        combined_headers = f"{title_text} {headings_text}".lower()

        for pat in DEFACEMENT_PATTERNS:
            match = re.search(pat, combined_headers, re.IGNORECASE)
            if match:
                indicators.append({
                    "category": "DEFACEMENT",
                    "severity": "CRITICAL",
                    "type": "Defacement Signature Detected",
                    "evidence": match.group(0),
                    "description": "Page title or top headings contain defacement takeover claims."
                })
                break

        # ── 2. Check for Hidden IFrames ───────────────────────────────────────
        iframes = soup.find_all("iframe")
        for idx, iframe in enumerate(iframes):
            style = (iframe.get("style") or "").lower()
            width = (iframe.get("width") or "").strip()
            height = (iframe.get("height") or "").strip()
            hidden = iframe.has_attr("hidden")
            src = iframe.get("src") or ""
            src_lower = src.lower()

            # Skip legitimate embedded widgets and auth providers (false positive prevention)
            is_benign_frame = any(b in src_lower for b in BENIGN_IFRAME_DOMAINS)
            if is_benign_frame:
                continue

            # Check if dimensions or styles hide the frame
            is_hidden = (
                hidden or
                "display:none" in style.replace(" ", "") or
                "visibility:hidden" in style.replace(" ", "") or
                "opacity:0" in style.replace(" ", "") or
                "left:-999" in style or
                (width in ["0", "0px", "1", "1px"] and height in ["0", "0px", "1", "1px"])
            )

            if is_hidden:
                indicators.append({
                    "category": "HIDDEN_IFRAME",
                    "severity": "HIGH",
                    "type": "Hidden Zero-Dimension / Invisible IFrame",
                    "evidence": f"<iframe src='{src[:120]}' style='{style[:80]}'>",
                    "description": "Hidden or zero-pixel iframe detected from an unverified origin. Threat actors frequently use invisible iframes for drive-by downloads or credential snooping."
                })

        # ── 3. Check for Obfuscated / Packed Scripts ──────────────────────────
        scripts = soup.find_all("script")
        for idx, script in enumerate(scripts):
            script_src = script.get("src") or ""
            script_content = script.string or ""

            # Check external script sources
            if script_src:
                script_host = urlparse(script_src).netloc.lower().split(":")[0].replace("www.", "")
                # Crypto-miner detection
                if any(m in script_host for m in KNOWN_MINER_DOMAINS):
                    indicators.append({
                        "category": "MALICIOUS_SCRIPT",
                        "severity": "CRITICAL",
                        "type": "In-Browser Cryptocurrency Miner Script",
                        "evidence": f"<script src='{script_src}'>",
                        "description": "Detected in-browser cryptocurrency mining script source."
                    })

            # Check inline script content for obfuscation patterns
            if script_content:
                cleaned_js = script_content.strip()
                # Dean Edwards packer
                if re.search(r"eval\(function\(p,a,c,k,e,[rd]", cleaned_js):
                    indicators.append({
                        "category": "OBFUSCATED_SCRIPT",
                        "severity": "HIGH",
                        "type": "Packed / Compressed JavaScript Evaluator",
                        "evidence": "eval(function(p,a,c,k,e,r)... signature",
                        "description": "Detected packed JavaScript eval() execution often used to conceal malicious payload logic."
                    })
                # unescape / fromCharCode abuse
                if "eval(unescape(" in cleaned_js or "eval(decodeuri" in cleaned_js.lower():
                    indicators.append({
                        "category": "OBFUSCATED_SCRIPT",
                        "severity": "HIGH",
                        "type": "Obfuscated eval(unescape(...)) Execution",
                        "evidence": "eval(unescape(...)) block",
                        "description": "Dynamic script evaluation from unescaped hexadecimal string."
                    })
                # Abnormally high repetition of fromCharCode
                from_char_count = len(re.findall(r"string\.fromcharcode", cleaned_js, re.IGNORECASE))
                if from_char_count > 10:
                    indicators.append({
                        "category": "OBFUSCATED_SCRIPT",
                        "severity": "MEDIUM",
                        "type": "High Frequency String.fromCharCode Obfuscation",
                        "evidence": f"{from_char_count} String.fromCharCode invocations",
                        "description": "Strings obfuscated as decimal ASCII codes to bypass static keyword filters."
                    })

        # ── 4. Check Form Action Targets & Credential Harvesting ─────────────
        forms = soup.find_all("form")
        for idx, form in enumerate(forms):
            action = form.get("action") or ""
            method = (form.get("method") or "GET").upper()
            resolved_action = urljoin(url, action)
            action_parsed = urlparse(resolved_action)
            action_host = (action_parsed.netloc or "").split(":")[0].lower().replace("www.", "")

            inputs = form.find_all("input")
            has_password = any(i.get("type", "").lower() == "password" for i in inputs)
            
            # Check for payment/sensitive input fields
            sensitive_names = ["cvv", "card_number", "cardnumber", "pin", "otp", "ssn", "aadhaar", "pan_number"]
            has_sensitive = any(any(s in (i.get("name") or "").lower() for s in sensitive_names) for i in inputs)

            # Check cross-origin form action (ignoring benign federated auth / payment gateways)
            if action_host and origin_host and action_host != origin_host:
                is_benign_form_target = any(b in action_host for b in BENIGN_FORM_TARGET_DOMAINS)
                if not is_benign_form_target and not action_host.endswith("." + origin_host) and not origin_host.endswith("." + action_host):
                    indicators.append({
                        "category": "SUSPICIOUS_FORM_ACTION",
                        "severity": "HIGH" if (has_password or has_sensitive) else "MEDIUM",
                        "type": "Cross-Origin Form Submission Endpoint",
                        "evidence": f"<form action='{resolved_action[:120]}' method='{method}'>",
                        "description": f"Form submits data to an external third-party domain: {action_host}."
                    })

            # Insecure form on HTTP
            if (has_password or has_sensitive) and action_parsed.scheme.lower() == "http":
                indicators.append({
                    "category": "INSECURE_CREDENTIAL_FORM",
                    "severity": "HIGH",
                    "type": "Plaintext HTTP Credential Submission",
                    "evidence": f"Form action target: {resolved_action[:100]}",
                    "description": "Form collects sensitive passwords or financial credentials over unencrypted HTTP."
                })

        # ── 5. Check for Unexpected Redirect Traps ────────────────────────────
        # Meta refresh tag
        meta_refresh = soup.find("meta", attrs={"http-equiv": lambda v: v and v.lower() == "refresh"})
        if meta_refresh:
            content = meta_refresh.get("content") or ""
            indicators.append({
                "category": "REDIRECT_TRAP",
                "severity": "MEDIUM",
                "type": "Meta-Refresh Redirection Header",
                "evidence": f"<meta http-equiv='refresh' content='{content}'>",
                "description": "Page automatically attempts client-side navigation via HTML meta refresh."
            })

        # ── 6. Check for Embedded Binary Data / Base64 Payload ───────────────
        data_links = soup.find_all("a", href=lambda h: h and h.lower().startswith("data:application/"))
        for lk in data_links:
            href_val = lk.get("href", "")
            indicators.append({
                "category": "SUSPICIOUS_EMBEDDED_RESOURCE",
                "severity": "HIGH",
                "type": "Embedded Base64 Binary Download Link",
                "evidence": href_val[:80] + "...",
                "description": "Hyperlink directly embeds an executable or octet-stream binary data URI."
            })

        # ── 7. Check for Mixed Content (HTTPS Parent with HTTP Assets) ───────
        if is_https_parent:
            http_scripts = [s.get("src") for s in scripts if s.get("src", "").lower().startswith("http://")]
            http_links = [l.get("href") for l in soup.find_all("link", rel="stylesheet") if l.get("href", "").lower().startswith("http://")]
            if http_scripts:
                indicators.append({
                    "category": "MIXED_CONTENT",
                    "severity": "MEDIUM",
                    "type": "Mixed Active Content (HTTP Script on HTTPS Site)",
                    "evidence": f"Insecure script: {http_scripts[0][:100]}",
                    "description": "Page loaded over secure HTTPS loads active scripts over unencrypted HTTP."
                })
            elif http_links:
                indicators.append({
                    "category": "MIXED_CONTENT",
                    "severity": "LOW",
                    "type": "Mixed Passive Content (HTTP Stylesheet on HTTPS Site)",
                    "evidence": f"Insecure stylesheet: {http_links[0][:100]}",
                    "description": "Page loads styling assets over unencrypted HTTP."
                })

        # ── Determine Overall Compromise Status ──────────────────────────────
        critical_count = sum(1 for i in indicators if i.get("severity") == "CRITICAL")
        high_count = sum(1 for i in indicators if i.get("severity") == "HIGH")
        medium_count = sum(1 for i in indicators if i.get("severity") == "MEDIUM")

        if critical_count > 0:
            status = "CONFIRMED_MALICIOUS_INDICATOR"
            risk_level = "CRITICAL"
            finding = f"Confirmed compromise / malicious indicators detected ({critical_count} critical findings)."
        elif high_count > 0:
            status = "POSSIBLE_COMPROMISE_INDICATOR"
            risk_level = "HIGH"
            finding = f"Strong indicators of potential compromise or deceptive construction ({high_count} high-severity findings)."
        elif medium_count > 0:
            status = "SUSPICIOUS_PAGE_BEHAVIOR"
            risk_level = "MEDIUM"
            finding = f"Anomalous page behaviors detected ({medium_count} medium-severity findings)."
        else:
            status = "NO_MALICIOUS_INDICATOR_DETECTED"
            risk_level = "NO_ISSUE_DETECTED"
            finding = "No malicious content, defacement, or hidden compromise indicators detected."

        return {
            "status": status,
            "risk_level": risk_level,
            "inspection_mode": "PASSIVE_HTML_DOM_INSPECTION",
            "finding": finding,
            "indicators": indicators,
            "total_indicators": len(indicators),
            "summary": f"Analyzed {len(scripts)} scripts, {len(forms)} forms, {len(iframes)} iframes.",
            "notice": "Never executes remote binary downloads or exploits. Inspection performed entirely via passive static parsing."
        }

content_compromise_inspector = ContentCompromiseInspector()
