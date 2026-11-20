"""
test_ssrf_security.py — Automated Security Test Suite for SSRF Vulnerability Prevention
Tests:
  - 127.0.0.1 (IPv4 loopback)
  - localhost / subdomains
  - Private IPv4 addresses (10.0.0.1, 192.168.1.1, 172.16.0.1)
  - IPv6 loopback (::1, [::1])
  - Cloud metadata (169.254.169.254, 169.254.169.250, metadata.google.internal)
  - Invalid schemes (file://, gopher://, ftp://)
  - Embedded credentials (http://user:pass@google.com)
  - Legitimate public domains (google.com, github.com)
"""

import asyncio
import sys
import unittest
from redirect_inspector import validate_target_url, redirect_inspector


class TestSSRFSecurity(unittest.IsolatedAsyncioTestCase):

    def test_loopback_ipv4(self):
        is_safe, msg, _, _ = validate_target_url("http://127.0.0.1/admin")
        self.assertFalse(is_safe)
        self.assertIn("loopback", msg.lower())

        is_safe, msg, _, _ = validate_target_url("http://127.0.0.254:8080")
        self.assertFalse(is_safe)
        self.assertIn("loopback", msg.lower())

    def test_localhost_hostname(self):
        is_safe, msg, _, _ = validate_target_url("http://localhost:8080")
        self.assertFalse(is_safe)

        is_safe, msg, _, _ = validate_target_url("http://sub.localhost:3000")
        self.assertFalse(is_safe)

    def test_private_ipv4_networks(self):
        # 10.0.0.0/8
        is_safe, msg, _, _ = validate_target_url("http://10.0.0.1/secret")
        self.assertFalse(is_safe)
        self.assertIn("private", msg.lower())

        # 192.168.0.0/16
        is_safe, msg, _, _ = validate_target_url("http://192.168.1.1/router")
        self.assertFalse(is_safe)
        self.assertIn("private", msg.lower())

        # 172.16.0.0/12
        is_safe, msg, _, _ = validate_target_url("http://172.16.0.1:9000")
        self.assertFalse(is_safe)
        self.assertIn("private", msg.lower())

    def test_ipv6_loopback_and_local(self):
        is_safe, msg, _, _ = validate_target_url("http://[::1]/")
        self.assertFalse(is_safe)

        is_safe, msg, _, _ = validate_target_url("http://[fe80::1]/")
        self.assertFalse(is_safe)

    def test_cloud_metadata(self):
        is_safe, msg, _, _ = validate_target_url("http://169.254.169.254/latest/meta-data/")
        self.assertFalse(is_safe)
        self.assertTrue("metadata" in msg.lower() or "link-local" in msg.lower())

        is_safe, msg, _, _ = validate_target_url("http://metadata.google.internal/computeMetadata/v1/")
        self.assertFalse(is_safe)

    def test_forbidden_schemes(self):
        is_safe, msg, _, _ = validate_target_url("file:///etc/passwd")
        self.assertFalse(is_safe)
        self.assertIn("invalid scheme", msg.lower())

        is_safe, msg, _, _ = validate_target_url("gopher://127.0.0.1:6379/_INFO")
        self.assertFalse(is_safe)
        self.assertIn("invalid scheme", msg.lower())

        is_safe, msg, _, _ = validate_target_url("ftp://ftp.is.co.za")
        self.assertFalse(is_safe)
        self.assertIn("invalid scheme", msg.lower())

    def test_embedded_credentials(self):
        is_safe, msg, _, _ = validate_target_url("http://admin:secret@google.com")
        self.assertFalse(is_safe)
        self.assertIn("embedded credentials", msg.lower())

    def test_valid_public_domain(self):
        is_safe, msg, norm_url, hostname = validate_target_url("https://www.google.com/search?q=test")
        self.assertTrue(is_safe)
        self.assertEqual(hostname, "www.google.com")

    async def test_inspector_blocks_ssrf(self):
        result = await redirect_inspector.inspect("http://127.0.0.1:8080/api/threats/all")
        self.assertFalse(result["fetch_success"])
        self.assertTrue(result["ssrf_blocked"])


if __name__ == "__main__":
    unittest.main()
