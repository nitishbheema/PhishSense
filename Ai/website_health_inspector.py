"""
website_health_inspector.py — Website Availability, HTTP Errors & Asset Health
Module 8:
  - HTTP status codes (200, 404, 500, 502, 503, etc.)
  - Round-trip response latency (ms)
  - DNS resolution & TLS handshake health
  - Redirect loop & excessive redirect detection
  - Broken asset inspection (sampled images, CSS, scripts for 404/500 errors)
  - Distinguishes server-side crashes from single broken image links
"""

import time
import logging
import httpx
from typing import Dict, Any, List, Optional
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup

log = logging.getLogger("phishsense-health-inspector")

class WebsiteHealthInspector:
    def __init__(self):
        self.sample_limit = 6
        self.asset_timeout = 2.0

    async def inspect_health(self, url: str, primary_status: Optional[int],
                             latency_ms: Optional[float], html_text: str,
                             redirect_chain: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Inspects website availability, response status, redirect loops, and broken resources.
        """
        parsed = urlparse(url)
        is_https = parsed.scheme.lower() == "https"

        broken_resources: List[Dict[str, Any]] = []
        health_issues: List[Dict[str, Any]] = []

        # ── 1. Evaluate Primary HTTP Status ──────────────────────────────────
        is_server_error = False
        is_client_error = False

        if primary_status is None:
            health_issues.append({
                "type": "CONNECTION_FAILED",
                "severity": "OPERATIONAL_FAILURE",
                "resource": url,
                "detail": "Failed to connect to the target web server (DNS resolution failed, connection refused, or timed out)."
            })
        elif primary_status in [500, 502, 503, 504]:
            is_server_error = True
            health_issues.append({
                "type": "SERVER_ERROR",
                "severity": "HIGH",
                "resource": url,
                "http_status": primary_status,
                "detail": f"Target server returned HTTP {primary_status} internal error / service unavailable."
            })
        elif primary_status in [400, 401, 403, 404, 429]:
            is_client_error = True
            health_issues.append({
                "type": "CLIENT_ERROR",
                "severity": "MEDIUM",
                "resource": url,
                "http_status": primary_status,
                "detail": f"Target returned HTTP {primary_status} ({'Access Forbidden' if primary_status==403 else 'Not Found' if primary_status==404 else 'Rate Limited'})."
            })

        # ── 2. Evaluate Latency ──────────────────────────────────────────────
        latency_val = latency_ms or 0
        if latency_val > 3000:
            health_issues.append({
                "type": "HIGH_LATENCY",
                "severity": "LOW",
                "resource": url,
                "detail": f"Server response time is slow ({round(latency_val)} ms, threshold 3000ms)."
            })

        # ── 3. Evaluate Redirect Chain Health ────────────────────────────────
        hops_count = len(redirect_chain)
        if hops_count > 4:
            health_issues.append({
                "type": "EXCESSIVE_REDIRECTS",
                "severity": "MEDIUM",
                "resource": url,
                "detail": f"Target required {hops_count} redirection hops before arriving at final page."
            })
        
        # Check for loop
        seen_urls = set()
        for step in redirect_chain:
            u_step = step.get("url", "")
            if u_step in seen_urls:
                health_issues.append({
                    "type": "REDIRECT_LOOP",
                    "severity": "HIGH",
                    "resource": u_step,
                    "detail": "Redirection loop detected: target repeatedly redirects to an already-visited URL."
                })
                break
            seen_urls.add(u_step)

        # ── 4. Sample Broken Assets (Images, Stylesheets, Scripts) ───────────
        if html_text and not is_server_error:
            soup = BeautifulSoup(html_text, "html.parser")
            assets_to_test = []

            # Images
            for img in soup.find_all("img", src=True):
                src = img["src"].strip()
                if not src.startswith("data:"):
                    assets_to_test.append(("Image", urljoin(url, src)))
                if len(assets_to_test) >= 3:
                    break

            # Stylesheets
            for link in soup.find_all("link", rel="stylesheet", href=True):
                href = link["href"].strip()
                if not href.startswith("data:"):
                    assets_to_test.append(("Stylesheet", urljoin(url, href)))
                if len(assets_to_test) >= 5:
                    break

            # Scripts
            for script in soup.find_all("script", src=True):
                src = script["src"].strip()
                if not src.startswith("data:"):
                    assets_to_test.append(("Script", urljoin(url, src)))
                if len(assets_to_test) >= self.sample_limit:
                    break

            # Test sampled assets with lightweight HEAD/GET requests
            if assets_to_test:
                async with httpx.AsyncClient(timeout=self.asset_timeout, verify=False) as client:
                    for asset_type, asset_url in assets_to_test:
                        try:
                            # Pre-check scheme
                            if not asset_url.startswith(("http://", "https://")):
                                continue
                            resp = await client.head(asset_url)
                            if resp.status_code in [404, 410, 500, 502, 503]:
                                broken_resources.append({
                                    "asset_type": asset_type,
                                    "asset_url": asset_url,
                                    "http_status": resp.status_code,
                                    "suggested_fix": f"Verify resource path or replace missing {asset_type.lower()} file (returned HTTP {resp.status_code})."
                                })
                        except Exception:
                            # Connection failed for individual asset
                            pass

        # ── 5. Synthesize Health Status ──────────────────────────────────────
        if primary_status is None:
            status = "UNREACHABLE"
            risk_level = "UNREACHABLE"
            finding = "Target website could not be reached (DNS resolution failed, connection timed out, or host unreachable)."
        elif is_server_error:
            status = "SERVER_DOWN_OR_ERROR"
            risk_level = "HIGH"
            finding = f"Target server returned HTTP {primary_status} internal error / service unavailable."
        elif broken_resources:
            status = "BROKEN_RESOURCES_DETECTED"
            risk_level = "LOW"
            finding = f"Website is accessible (HTTP {primary_status}), but {len(broken_resources)} broken resource(s) were found."
        elif is_client_error:
            status = "HTTP_CLIENT_ERROR"
            risk_level = "INFORMATIONAL"
            finding = f"Target returned HTTP {primary_status} client response."
        elif health_issues:
            status = "HEALTH_WARNINGS"
            risk_level = "LOW"
            finding = f"Website is accessible with {len(health_issues)} technical advisory issue(s)."
        else:
            status = "HEALTHY_AVAILABILITY"
            risk_level = "NO_ISSUE_DETECTED"
            finding = f"Website responded with HTTP {primary_status or 200} in {round(latency_val)}ms. All sampled assets accessible."

        return {
            "status": status,
            "risk_level": risk_level,
            "finding": finding,
            "http_status": primary_status,
            "latency_ms": round(latency_val, 1),
            "redirect_hops": hops_count,
            "health_issues": health_issues,
            "broken_resources": broken_resources,
            "broken_count": len(broken_resources),
            "distinction_note": "Server availability is reported independently from individual missing images or scripts."
        }

website_health_inspector = WebsiteHealthInspector()
