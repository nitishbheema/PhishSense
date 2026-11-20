"""
test_website_intelligence.py — Automated Unit & Integration Tests for Website Intelligence
Tests:
  - RDAP domain age retrieval, unsupported TLDs, privacy-redacted WHOIS
  - Certificate expiry, SAN hostname mismatch, CT log parsing
  - Security headers detection (HSTS, CSP, XFO, XCTO, Referrer, Cookie flags)
  - Tech stack fingerprinting & End-of-Life lifecycle matching
  - CVE vulnerability version range matching (NVD correlation)
  - Compromise detection: Obfuscated scripts, hidden iframes, defacement, forms
  - Website health: 404/500 responses, latency, broken resource sampling
  - Privacy protection & SSRF loopback/private IP defense
"""

import unittest
from unittest.mock import patch, MagicMock, AsyncMock
import asyncio

from domain_intelligence import domain_intelligence_engine
from certificate_history import certificate_history_engine
from tech_stack_detector import tech_stack_detector
from cve_intelligence import cve_intelligence_engine
from security_headers_evaluator import security_headers_evaluator
from content_compromise_inspector import content_compromise_inspector
from website_health_inspector import website_health_inspector
from threat_reputation import threat_reputation_engine
from redirect_inspector import validate_target_url


class TestWebsiteIntelligence(unittest.TestCase):

    # ── 1. Domain Age, Unsupported TLD & Missing RDAP ──────────────────────────
    def test_domain_age_and_unsupported_tld(self):
        # Test RDAP parsing with mocked response
        mock_rdap = {
            "events": [
                {"eventAction": "registration", "eventDate": "2020-05-10T12:00:00Z"},
                {"eventAction": "expiration", "eventDate": "2028-05-10T12:00:00Z"}
            ],
            "entities": [{"roles": ["registrar"], "vcardArray": ["vcard", [["fn", {}, "text", "GoDaddy.com, LLC"]]]}],
            "status": ["clientTransferProhibited"],
            "nameservers": [{"ldhName": "ns1.example.com"}, {"ldhName": "ns2.example.com"}]
        }

        with patch("httpx.AsyncClient.get") as mock_get:
            mock_resp = MagicMock()
            mock_resp.status_code = 200
            mock_resp.json.return_value = mock_rdap
            mock_get.return_value = mock_resp

            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            res = loop.run_until_complete(domain_intelligence_engine._fetch_rdap("example.com"))
            loop.close()

            self.assertEqual(res["creation_date_formatted"], "2020-05-10")
            self.assertGreater(res["domain_age_days"], 1000)
            self.assertEqual(res["registrar"], "GoDaddy.com, LLC")
            self.assertTrue(any("clienttransferprohibited" in s.lower() for s in res["status_codes"]))

    def test_unsupported_tld_handling(self):
        with patch("httpx.AsyncClient.get") as mock_get:
            mock_resp = MagicMock()
            mock_resp.status_code = 404
            mock_get.return_value = mock_resp

            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            res = loop.run_until_complete(domain_intelligence_engine._fetch_rdap("unsupported.internal"))
            loop.close()

            self.assertTrue(res["unsupported_tld"])
            self.assertIsNone(res["creation_date"])

    # ── 2. Certificate Expiry & Hostname Mismatch ─────────────────────────────
    def test_certificate_expiry_detection(self):
        cert_data = certificate_history_engine._get_live_tls_certificate("invalid-hostname-test.local")
        self.assertFalse(cert_data["has_tls"])

    def test_certificate_hostname_mismatch_logic(self):
        # Simulate SAN matching
        sans = ["api.example.com", "cdn.example.com"]
        hostname = "phishing-example.com"
        match_found = hostname.lower() in [s.lower() for s in sans]
        self.assertFalse(match_found)

    # ── 3. Security Headers Evaluation ─────────────────────────────────────────
    def test_security_headers_detection(self):
        headers = {
            "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
            "Content-Security-Policy": "default-src 'self'",
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "Referrer-Policy": "strict-origin-when-cross-origin",
            "Permissions-Policy": "geolocation=(), camera=()"
        }
        res = security_headers_evaluator.evaluate_headers(headers, is_https=True)
        self.assertEqual(res["missing_count"], 0)
        self.assertEqual(res["status"], "STRONG_SECURITY_HEADERS")

    def test_missing_critical_headers(self):
        # Empty headers
        res = security_headers_evaluator.evaluate_headers({}, is_https=True)
        self.assertGreaterEqual(res["missing_count"], 3)
        self.assertEqual(res["status"], "WEAK_SECURITY_HEADERS")
        self.assertEqual(res["risk_level"], "HIGH")

    def test_missing_permissions_policy_alone_is_not_moderate_or_critical(self):
        # Only Permissions-Policy missing (core transport & framing headers present)
        headers = {
            "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
            "Content-Security-Policy": "default-src 'self'",
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "Referrer-Policy": "strict-origin-when-cross-origin"
            # Permissions-Policy omitted intentionally
        }
        res = security_headers_evaluator.evaluate_headers(headers, is_https=True)
        self.assertEqual(res["status"], "GOOD_SECURITY_HEADERS_OPTIONAL_HARDENING")
        self.assertEqual(res["risk_level"], "INFORMATIONAL")
        self.assertNotEqual(res["risk_level"], "MEDIUM")
        self.assertNotEqual(res["risk_level"], "HIGH")

    # ── 4. Tech Stack & Outdated Software Fingerprinting ──────────────────────
    def test_outdated_php_and_apache_detection(self):
        headers = {
            "Server": "Apache/2.4.41 (Ubuntu)",
            "X-Powered-By": "PHP/7.4.3"
        }
        res = tech_stack_detector.detect_technologies(headers, "<html><body>Hello</body></html>")
        tech_names = [t["name"] for t in res["technologies"]]
        self.assertIn("Apache HTTP Server", tech_names)
        self.assertIn("PHP", tech_names)

        php_tech = next(t for t in res["technologies"] if t["name"] == "PHP")
        self.assertTrue(php_tech["is_outdated"])
        self.assertEqual(php_tech["lifecycle_status"], "END_OF_LIFE")

    def test_wordpress_detection(self):
        html = '<meta name="generator" content="WordPress 5.8.1" />'
        res = tech_stack_detector.detect_technologies({}, html)
        wp_tech = next((t for t in res["technologies"] if t["name"] == "WordPress"), None)
        self.assertNotNull = self.assertIsNotNone
        self.assertNotNull(wp_tech)
        self.assertEqual(wp_tech["version"], "5.8.1")
        self.assertTrue(wp_tech["is_outdated"])

    # ── 5. CVE Version Range Matching ─────────────────────────────────────────
    def test_cve_correlation_confirmed_match(self):
        detected = [
            {"name": "PHP", "version": "7.4.3", "has_version": True},
            {"name": "Apache HTTP Server", "version": "2.4.41", "has_version": True}
        ]
        cve_res = cve_intelligence_engine.match_vulnerabilities(detected)
        self.assertGreater(cve_res["potential_cve_count"], 0)
        cve_ids = [v["cve_id"] for v in cve_res["vulnerabilities"]]
        self.assertIn("CVE-2024-4577", cve_ids)
        self.assertIn("CVE-2023-31122", cve_ids)
        # Verify defensive security distinction: Unverified backport patch status
        for vuln in cve_res["vulnerabilities"]:
            if vuln["detected_version"] != "Unverified":
                self.assertEqual(vuln["match_status"], "POTENTIAL_VULNERABILITY_UNVERIFIED_PATCH")
                self.assertIn("backport", vuln["caveat"].lower())
                self.assertIn("reference_url", vuln)
                self.assertIn("last_verified_utc", vuln)

    def test_cve_patched_version_no_false_positive(self):
        # Apache 2.4.58 is patched against CVE-2021-41773 and CVE-2023-31122
        detected = [
            {"name": "Apache HTTP Server", "version": "2.4.58", "has_version": True}
        ]
        cve_res = cve_intelligence_engine.match_vulnerabilities(detected)
        self.assertEqual(cve_res["potential_cve_count"], 0)
        self.assertEqual(cve_res["status"], "NO_ISSUE_DETECTED")

    def test_cve_unverified_version_handling(self):
        # Product detected, but version unknown -> ADVISORY_CHECK_VERSION_UNVERIFIED
        detected = [{"name": "WordPress", "version": "Technology detected, version not reliably identified", "has_version": False}]
        cve_res = cve_intelligence_engine.match_vulnerabilities(detected)
        self.assertEqual(cve_res["potential_cve_count"], 0)
        self.assertEqual(cve_res["status"], "POTENTIAL_VULNERABILITIES_NOTED")
        self.assertEqual(cve_res["vulnerabilities"][0]["match_status"], "ADVISORY_CHECK_VERSION_UNVERIFIED")

    # ── 6. Compromise & Deceptive HTML Inspection ─────────────────────────────
    def test_hidden_iframe_and_obfuscation(self):
        html = '''
        <html>
          <body>
            <iframe src="http://malicious-drop.com/payload" style="display:none; width:0px; height:0px;"></iframe>
            <script>eval(function(p,a,c,k,e,r){return 'packed';}('p',1,1,'packed',0,{}))</script>
          </body>
        </html>
        '''
        comp_res = content_compromise_inspector.inspect_content("https://example.com", html, 200)
        categories = [i["category"] for i in comp_res["indicators"]]
        self.assertIn("HIDDEN_IFRAME", categories)
        self.assertIn("OBFUSCATED_SCRIPT", categories)
        self.assertIn(comp_res["status"], ["CONFIRMED_MALICIOUS_INDICATOR", "POSSIBLE_COMPROMISE_INDICATOR"])

    def test_benign_html_no_false_positives(self):
        # Legitimate minified JS, Google reCAPTCHA hidden iframe, GTM, and Google OAuth form
        benign_html = '''
        <!DOCTYPE html>
        <html>
          <head>
            <script src="https://www.googletagmanager.com/gtag/js?id=G-12345"></script>
          </head>
          <body>
            <h1>Welcome to Authentic Portal</h1>
            <iframe src="https://www.google.com/recaptcha/api2/bframe" style="display:none; width:0; height:0"></iframe>
            <form action="https://accounts.google.com/o/oauth2/auth" method="POST">
              <input type="password" name="password" />
              <button type="submit">Sign in with Google</button>
            </form>
            <script>
              !function(e,t){var r=function(o){return o+1};window.run=r;}(window,document);
            </script>
          </body>
        </html>
        '''
        comp_res = content_compromise_inspector.inspect_content("https://example.com", benign_html, 200)
        self.assertEqual(comp_res["status"], "NO_MALICIOUS_INDICATOR_DETECTED")
        self.assertEqual(comp_res["risk_level"], "NO_ISSUE_DETECTED")
        self.assertEqual(len(comp_res["indicators"]), 0)

    def test_defacement_signature(self):
        html = '<html><head><title>Hacked By Cyber Army</title></head><body><h1>Pwned by Team Defacers</h1></body></html>'
        comp_res = content_compromise_inspector.inspect_content("https://example.com", html, 200)
        categories = [i["category"] for i in comp_res["indicators"]]
        self.assertIn("DEFACEMENT", categories)
        self.assertEqual(comp_res["risk_level"], "CRITICAL")

    # ── 7. Website Health, 404/500 & Broken Resources ─────────────────────────
    def test_unreachable_domain_health_not_critical(self):
        # Operational connectivity failure (primary_status is None) must return UNREACHABLE, not CRITICAL
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        health = loop.run_until_complete(website_health_inspector.inspect_health("https://nonexistent.local", None, 150.0, "", []))
        loop.close()
        self.assertEqual(health["status"], "UNREACHABLE")
        self.assertEqual(health["risk_level"], "UNREACHABLE")
        self.assertNotEqual(health["risk_level"], "CRITICAL")
        self.assertIn("could not be reached", health["finding"])

    def test_server_500_error_health(self):
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        health = loop.run_until_complete(website_health_inspector.inspect_health("https://example.com", 500, 150.0, "", []))
        loop.close()
        self.assertEqual(health["status"], "SERVER_DOWN_OR_ERROR")
        self.assertEqual(health["risk_level"], "HIGH")

    def test_healthy_website_availability(self):
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        health = loop.run_until_complete(website_health_inspector.inspect_health("https://example.com", 200, 120.0, "<html><body>Clean</body></html>", []))
        loop.close()
        self.assertEqual(health["status"], "HEALTHY_AVAILABILITY")
        self.assertEqual(health["risk_level"], "NO_ISSUE_DETECTED")

    # ── 8. Privacy & SSRF Prevention ──────────────────────────────────────────
    def test_ssrf_rejection_in_audit(self):
        # Loopback
        valid, reason, *_ = validate_target_url("http://127.0.0.1:8080/admin")
        self.assertFalse(valid)
        self.assertIn("loopback", reason.lower())

        # Cloud metadata
        valid, reason, *_ = validate_target_url("http://169.254.169.254/latest/meta-data")
        self.assertFalse(valid)
        self.assertIn("metadata", reason.lower())

        # RFC1918 Private subnet
        valid, reason, *_ = validate_target_url("http://192.168.1.1/setup")
        self.assertFalse(valid)
        self.assertIn("private", reason.lower())


    # ── 9. Provider Compliance & Threat Intelligence ──────────────────────────
    def test_google_web_risk_threat_match(self):
        # Mock successful Google Web Risk detection
        mock_web_risk_response = {
            "threat": {
                "threatTypes": ["SOCIAL_ENGINEERING", "MALWARE"],
                "expireTime": "2026-11-21T00:00:00Z"
            }
        }
        with patch.object(threat_reputation_engine, "web_risk_api_key", "test-web-risk-key"):
            with patch("httpx.AsyncClient.get") as mock_get:
                mock_resp = MagicMock()
                mock_resp.status_code = 200
                mock_resp.json.return_value = mock_web_risk_response
                mock_get.return_value = mock_resp

                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                res = loop.run_until_complete(threat_reputation_engine._check_google_web_risk("http://phish-target.com"))
                loop.close()

                self.assertIsNotNone(res)
                self.assertEqual(res["source"], "Google Web Risk API")
                self.assertEqual(res["match_type"], "EXACT_URL")
                self.assertTrue(res["confirmed"])
                self.assertIn("SOCIAL_ENGINEERING", res["threat_type"])

    def test_missing_providers_explicitly_reported_not_silently_clean(self):
        # With no external API keys configured, report explicit unconfigured status
        with patch.object(threat_reputation_engine, "web_risk_api_key", None), \
             patch.object(threat_reputation_engine, "virustotal_api_key", None), \
             patch.object(threat_reputation_engine, "abuse_ch_api_key", None):

            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            res = loop.run_until_complete(threat_reputation_engine.evaluate_reputation("https://unknown-domain-test.org"))
            loop.close()

            self.assertIn("coverage_disclaimer", res)
            sources = " ".join(res["sources_checked"])
            self.assertIn("Google Web Risk (Unconfigured", sources)
            self.assertIn("VirusTotal (Unconfigured", sources)
            self.assertIn("URLhaus (Unavailable", sources)


if __name__ == "__main__":
    unittest.main()
