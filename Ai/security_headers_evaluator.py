"""
security_headers_evaluator.py — TLS & HTTP Security Configuration Analysis
Module 7:
  - HSTS (Strict-Transport-Security) evaluation
  - Content-Security-Policy (CSP) strength assessment
  - X-Content-Type-Options nosniff verification
  - Clickjacking defense (X-Frame-Options / frame-ancestors)
  - Referrer-Policy and Permissions-Policy audit
  - Cookie security attributes (Secure, HttpOnly, SameSite)
  - Information disclosure in response headers
  - Generates actionable configuration recommendations
"""

import re
import logging
from typing import Dict, Any, List, Optional

log = logging.getLogger("phishsense-security-headers")

class SecurityHeadersEvaluator:
    def __init__(self):
        pass

    def evaluate_headers(self, headers: Dict[str, str], is_https: bool = True) -> Dict[str, Any]:
        """
        Evaluates HTTP response headers and cookie security flags.
        """
        norm_headers = {k.lower(): v for k, v in headers.items()}
        header_checks: List[Dict[str, Any]] = []

        # ── 1. Strict-Transport-Security (HSTS) ──────────────────────────────
        hsts_val = norm_headers.get("strict-transport-security")
        if hsts_val:
            max_age_match = re.search(r"max-age=(\d+)", hsts_val, re.IGNORECASE)
            max_age = int(max_age_match.group(1)) if max_age_match else 0
            has_subdomains = "includesubdomains" in hsts_val.lower()
            has_preload = "preload" in hsts_val.lower()

            if max_age >= 31536000:
                hsts_status = "OPTIMAL"
                hsts_note = f"HSTS is actively configured with a 1-year duration ({max_age} seconds)."
            elif max_age > 0:
                hsts_status = "WARNING"
                hsts_note = f"HSTS is enabled but duration is short ({max_age} seconds, recommended >= 31536000)."
            else:
                hsts_status = "WARNING"
                hsts_note = "HSTS header is present but max-age is zero or invalid."

            header_checks.append({
                "header": "Strict-Transport-Security",
                "status": hsts_status,
                "value": hsts_val,
                "importance": "HIGH",
                "finding": hsts_note,
                "recommendation": "Maintain 'max-age=31536000; includeSubDomains; preload' for top-tier transport security."
            })
        else:
            header_checks.append({
                "header": "Strict-Transport-Security",
                "status": "MISSING",
                "value": None,
                "importance": "HIGH",
                "finding": "HSTS header is missing. Browsers may connect via insecure HTTP on first visit, enabling SSL-stripping attacks.",
                "recommendation": "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains' to all HTTPS responses."
            })

        # ── 2. Content-Security-Policy (CSP) ─────────────────────────────────
        csp_val = norm_headers.get("content-security-policy")
        if csp_val:
            has_unsafe_inline = "'unsafe-inline'" in csp_val.lower()
            has_unsafe_eval = "'unsafe-eval'" in csp_val.lower()

            if not has_unsafe_inline and not has_unsafe_eval:
                csp_status = "OPTIMAL"
                csp_note = "CSP is configured without unsafe-inline or unsafe-eval flags."
            else:
                csp_status = "WARNING"
                flags = []
                if has_unsafe_inline: flags.append("'unsafe-inline'")
                if has_unsafe_eval: flags.append("'unsafe-eval'")
                csp_note = f"CSP is present but permits {', '.join(flags)}, weakening Cross-Site Scripting (XSS) defenses."

            header_checks.append({
                "header": "Content-Security-Policy",
                "status": csp_status,
                "value": csp_val[:120] + ("..." if len(csp_val) > 120 else ""),
                "importance": "HIGH",
                "finding": csp_note,
                "recommendation": "Refactor inline scripts to use cryptographic nonces or hashes instead of 'unsafe-inline'."
            })
        else:
            header_checks.append({
                "header": "Content-Security-Policy",
                "status": "MISSING",
                "value": None,
                "importance": "HIGH",
                "finding": "CSP is missing. The browser cannot restrict where scripts, stylesheets, or iframes can be loaded from.",
                "recommendation": "Define a Content-Security-Policy header starting with 'default-src 'self''."
            })

        # ── 3. X-Content-Type-Options ────────────────────────────────────────
        xcto_val = norm_headers.get("x-content-type-options")
        if xcto_val and "nosniff" in xcto_val.lower():
            header_checks.append({
                "header": "X-Content-Type-Options",
                "status": "OPTIMAL",
                "value": xcto_val,
                "importance": "MEDIUM",
                "finding": "MIME-type sniffing protection is active ('nosniff').",
                "recommendation": "Configured correctly."
            })
        else:
            header_checks.append({
                "header": "X-Content-Type-Options",
                "status": "MISSING",
                "value": xcto_val,
                "importance": "MEDIUM",
                "finding": "Header is missing or not set to 'nosniff'. Browsers may attempt to guess the MIME type of files, enabling script execution from images.",
                "recommendation": "Add 'X-Content-Type-Options: nosniff' header."
            })

        # ── 4. X-Frame-Options / Frame Ancestors ─────────────────────────────
        xfo_val = norm_headers.get("x-frame-options")
        has_frame_ancestors = csp_val and "frame-ancestors" in csp_val.lower()

        if xfo_val and xfo_val.lower() in ["deny", "sameorigin"]:
            header_checks.append({
                "header": "X-Frame-Options",
                "status": "OPTIMAL",
                "value": xfo_val,
                "importance": "HIGH",
                "finding": f"Clickjacking protection enabled ({xfo_val.upper()}).",
                "recommendation": "Configured correctly."
            })
        elif has_frame_ancestors:
            header_checks.append({
                "header": "X-Frame-Options / frame-ancestors",
                "status": "OPTIMAL",
                "value": "Protected via CSP frame-ancestors",
                "importance": "HIGH",
                "finding": "Clickjacking protection is enforced through CSP frame-ancestors.",
                "recommendation": "Configured correctly."
            })
        else:
            header_checks.append({
                "header": "X-Frame-Options",
                "status": "MISSING",
                "value": None,
                "importance": "HIGH",
                "finding": "Frame embedding is unrestricted. Attackers can embed this page in a malicious iframe to perform clickjacking attacks.",
                "recommendation": "Add 'X-Frame-Options: SAMEORIGIN' or configure 'frame-ancestors 'self'' in CSP."
            })

        # ── 5. Referrer-Policy ───────────────────────────────────────────────
        ref_val = norm_headers.get("referrer-policy")
        if ref_val:
            header_checks.append({
                "header": "Referrer-Policy",
                "status": "OPTIMAL",
                "value": ref_val,
                "importance": "LOW",
                "finding": f"Referrer-Policy is specified ('{ref_val}').",
                "recommendation": "Configured correctly."
            })
        else:
            header_checks.append({
                "header": "Referrer-Policy",
                "status": "MISSING",
                "value": None,
                "importance": "LOW",
                "finding": "Referrer-Policy is not explicitly set; browser default will apply.",
                "recommendation": "Add 'Referrer-Policy: strict-origin-when-cross-origin' to protect internal URL paths."
            })

        # ── 6. Permissions-Policy ────────────────────────────────────────────
        perm_val = norm_headers.get("permissions-policy") or norm_headers.get("feature-policy")
        if perm_val:
            header_checks.append({
                "header": "Permissions-Policy",
                "status": "OPTIMAL",
                "value": perm_val[:80],
                "importance": "LOW",
                "finding": "Permissions-Policy restricts browser hardware API access.",
                "recommendation": "Configured correctly."
            })
        else:
            header_checks.append({
                "header": "Permissions-Policy",
                "status": "MISSING",
                "value": None,
                "importance": "LOW",
                "finding": "Permissions-Policy is missing. Hardware APIs (camera, geolocation) are not restricted at the header level.",
                "recommendation": "Add 'Permissions-Policy: geolocation=(), camera=(), microphone=()' if not utilized."
            })

        # ── 7. Cookie Security Attributes ────────────────────────────────────
        cookie_header = norm_headers.get("set-cookie", "")
        cookie_checks = []
        if cookie_header:
            has_secure = "secure" in cookie_header.lower()
            has_httponly = "httponly" in cookie_header.lower()
            has_samesite = "samesite" in cookie_header.lower()

            cookie_checks.append({
                "attribute": "Secure",
                "present": has_secure,
                "status": "OPTIMAL" if has_secure else "WARNING",
                "note": "Ensures cookies are only transmitted over encrypted HTTPS connections."
            })
            cookie_checks.append({
                "attribute": "HttpOnly",
                "present": has_httponly,
                "status": "OPTIMAL" if has_httponly else "WARNING",
                "note": "Prevents client-side JavaScript from accessing session cookies (mitigates XSS cookie theft)."
            })
            cookie_checks.append({
                "attribute": "SameSite",
                "present": has_samesite,
                "status": "OPTIMAL" if has_samesite else "WARNING",
                "note": "Controls whether cookies are sent with cross-site requests (mitigates CSRF attacks)."
            })

        # ── 8. Information Disclosure Headers ────────────────────────────────
        server_val = norm_headers.get("server")
        x_powered = norm_headers.get("x-powered-by")
        disclosure_notes = []
        if server_val and re.search(r"[0-9]+\.[0-9]+", server_val):
            disclosure_notes.append(f"Server header exposes exact version: '{server_val}'")
        if x_powered:
            disclosure_notes.append(f"X-Powered-By header exposes backend runtime: '{x_powered}'")

        # ── Calculate Summary Score (Severity & Importance Calibrated) ───────
        missing_count = sum(1 for c in header_checks if c["status"] == "MISSING")
        missing_critical_count = sum(1 for c in header_checks if c["status"] == "MISSING" and c.get("importance") == "HIGH")
        missing_optional_count = sum(1 for c in header_checks if c["status"] == "MISSING" and c.get("importance") == "LOW")
        warning_count = sum(1 for c in header_checks if c["status"] == "WARNING")
        optimal_count = sum(1 for c in header_checks if c["status"] == "OPTIMAL")

        if missing_critical_count >= 3:
            status = "WEAK_SECURITY_HEADERS"
            risk_level = "HIGH"
            finding = f"{missing_critical_count} critical security headers are missing (e.g. HSTS, CSP, X-Frame-Options)."
        elif missing_critical_count >= 1:
            status = "PARTIAL_SECURITY_HEADERS"
            risk_level = "MEDIUM"
            missing_names = ", ".join([c["header"] for c in header_checks if c["status"] == "MISSING" and c.get("importance") == "HIGH"])
            finding = f"{missing_critical_count} critical security header(s) missing ({missing_names})."
        elif warning_count > 0:
            status = "SUBOPTIMAL_SECURITY_HEADERS"
            risk_level = "LOW"
            finding = f"Core security headers are present, but {warning_count} header setting(s) contain suboptimal policies."
        elif missing_optional_count > 0:
            status = "GOOD_SECURITY_HEADERS_OPTIONAL_HARDENING"
            risk_level = "INFORMATIONAL"
            missing_opts = ", ".join([c["header"] for c in header_checks if c["status"] == "MISSING"])
            finding = f"Core transport and framing headers (HSTS, CSP, XFO, XCTO) are active; optional hardening headers ({missing_opts}) can be added."
        else:
            status = "STRONG_SECURITY_HEADERS"
            risk_level = "NO_ISSUE_DETECTED"
            finding = "All primary security headers are properly implemented and configured."

        return {
            "status": status,
            "risk_level": risk_level,
            "finding": finding,
            "optimal_count": optimal_count,
            "warning_count": warning_count,
            "missing_count": missing_count,
            "header_checks": header_checks,
            "cookie_checks": cookie_checks,
            "information_disclosure": disclosure_notes,
            "remediation_guidance": "Missing headers represent configuration weaknesses, not necessarily active malware. Implementing them prevents future clickjacking, XSS, and SSL-stripping."
        }

security_headers_evaluator = SecurityHeadersEvaluator()
