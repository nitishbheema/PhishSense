"""
redirect_inspector.py — Multi-Hop Redirect Tracer and Safe Live Webpage Inspector
Performs:
  1. Full hop-by-hop redirect chain analysis
  2. Domain crossing detection (e.g. shortener -> landing domain)
  3. Safe DOM signal extraction (forms, passwords, external actions, visual anchor spoofing)
  4. Script and evasion technique analysis
"""

import re
import logging
from typing import Dict, Any, List, Optional
from urllib.parse import urlparse
import httpx
from bs4 import BeautifulSoup

log = logging.getLogger("phishsense-redirect-inspector")

COMMON_AUTH_KEYWORDS = {
    "login", "signin", "verify", "verification", "secure", "security",
    "account", "banking", "authenticate", "portal", "password", "wallet"
}

SUSPICIOUS_JS_PATTERNS = [
    "eval(", "document.write(", "window.location=", "unescape(",
    "string.fromcharcode(", "atob(", "\\x", "\\u00"
]

class RedirectAndWebpageInspector:
    def __init__(self, timeout: float = 4.0, max_hops: int = 5):
        self.timeout = timeout
        self.max_hops = max_hops
        self.headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
        }

    async def inspect(self, initial_url: str) -> Dict[str, Any]:
        url = initial_url.strip()
        if not url.startswith(("http://", "https://")):
            url = "http://" + url

        initial_domain = urlparse(url).netloc.lower().split(":")[0].replace("www.", "")

        chain: List[Dict[str, Any]] = []
        html_content = ""
        final_url = url
        final_status = None
        fetch_success = False
        error_msg = None

        try:
            async with httpx.AsyncClient(
                timeout=httpx.Timeout(self.timeout, connect=2.0),
                follow_redirects=True,
                max_redirects=self.max_hops,
                headers=self.headers,
                verify=False,
            ) as client:
                resp = await client.get(url)
                final_url = str(resp.url)
                final_status = resp.status_code
                fetch_success = True
                html_content = resp.text[:400_000]

                # Trace history hops
                for idx, hop_resp in enumerate(resp.history):
                    chain.append({
                        "hop": idx,
                        "url": str(hop_resp.url),
                        "status": hop_resp.status_code,
                        "domain": urlparse(str(hop_resp.url)).netloc.lower().split(":")[0].replace("www.", "")
                    })
                # Add final destination
                chain.append({
                    "hop": len(chain),
                    "url": final_url,
                    "status": final_status,
                    "domain": urlparse(final_url).netloc.lower().split(":")[0].replace("www.", "")
                })
        except httpx.TimeoutException:
            error_msg = "Connection timed out during live inspection"
        except httpx.ConnectError:
            error_msg = "Host connection failed / server unreachable"
        except Exception as ex:
            error_msg = f"Live inspection skipped: {str(ex)[:80]}"

        final_domain = urlparse(final_url).netloc.lower().split(":")[0].replace("www.", "")
        redirect_count = max(0, len(chain) - 1)
        cross_domain = (initial_domain != final_domain) if (fetch_success and redirect_count > 0) else False

        # Parse DOM signals if HTML was retrieved
        dom_signals = self._analyze_dom(final_url, final_domain, html_content) if fetch_success else {}

        # Calculate live webpage risk
        webpage_risk = self._compute_webpage_risk(dom_signals, cross_domain, redirect_count)

        return {
            "fetch_success": fetch_success,
            "error_msg": error_msg,
            "initial_url": initial_url,
            "final_url": final_url,
            "initial_domain": initial_domain,
            "final_domain": final_domain,
            "http_status": final_status,
            "redirect_count": redirect_count,
            "cross_domain_redirect": cross_domain,
            "redirect_chain": chain,
            "dom_signals": dom_signals,
            "webpage_risk_score": webpage_risk,
        }

    def _analyze_dom(self, url: str, domain: str, html: str) -> Dict[str, Any]:
        if not html:
            return {}
        try:
            soup = BeautifulSoup(html, "html.parser")
            forms = soup.find_all("form")
            pwd_fields = soup.find_all("input", {"type": re.compile(r"password", re.I)})

            # Form Action destination analysis
            suspicious_actions = 0
            for form in forms:
                action = form.get("action", "").strip()
                if action:
                    if action.startswith("http"):
                        action_dom = urlparse(action).netloc.lower().split(":")[0].replace("www.", "")
                        if action_dom and action_dom != domain and not action_dom.endswith("." + domain):
                            suspicious_actions += 1
                    elif action in ["#", "about:blank", "javascript:void(0)", ""]:
                        suspicious_actions += 1

            # Deceptive Visual Anchor Spoofing
            anchors = soup.find_all("a", href=True)
            spoofed_links = []
            for a in anchors:
                href = a.get("href", "").strip()
                disp = a.get_text(strip=True)
                if not href or not disp or " " in disp:
                    continue
                if disp.lower().startswith(("http://", "https://", "www.")) or re.match(r"^[a-zA-Z0-9-]+\.(com|org|net|edu|gov|io|co|in|xyz|app|dev|me|info)(/[^\s]*)?$", disp, re.IGNORECASE):
                    norm_disp = disp if disp.startswith(("http://", "https://")) else "http://" + disp
                    norm_href = href if href.startswith(("http://", "https://")) else "http://" + href
                    try:
                        d_host = urlparse(norm_disp).netloc.lower().split(":")[0].replace("www.", "")
                        h_host = urlparse(norm_href).netloc.lower().split(":")[0].replace("www.", "")
                        tld = d_host.split(".")[-1]
                        if tld.isalpha() and len(tld) >= 2 and d_host and h_host:
                            if d_host != h_host and not d_host.endswith("." + h_host) and not h_host.endswith("." + d_host):
                                spoofed_links.append({
                                    "displayed": d_host,
                                    "actual": h_host,
                                    "text": disp[:60]
                                })
                    except Exception:
                        pass

            title_tag = soup.find("title")
            page_title = title_tag.get_text(strip=True).lower() if title_tag else ""

            # Check title auth mismatch
            title_has_auth = any(w in page_title for w in COMMON_AUTH_KEYWORDS)
            domain_has_auth = any(w in domain for w in COMMON_AUTH_KEYWORDS)
            title_mismatch = (title_has_auth and not domain_has_auth)

            # Suspicious JS
            inline_scripts = " ".join(s.get_text() for s in soup.find_all("script"))
            sus_js_count = sum(1 for p in SUSPICIOUS_JS_PATTERNS if p in inline_scripts.lower())
            right_click_disabled = "contextmenu" in inline_scripts.lower() or "event.button==2" in inline_scripts

            iframes = soup.find_all("iframe")

            return {
                "form_count": len(forms),
                "has_password_field": len(pwd_fields) > 0,
                "password_field_count": len(pwd_fields),
                "suspicious_action_count": suspicious_actions,
                "has_suspicious_action": suspicious_actions > 0,
                "spoofed_hyperlinks_count": len(spoofed_links),
                "has_spoofed_hyperlinks": len(spoofed_links) > 0,
                "spoofed_links_sample": spoofed_links[:3],
                "page_title": page_title[:80],
                "title_auth_mismatch": title_mismatch,
                "suspicious_js_count": sus_js_count,
                "right_click_disabled": right_click_disabled,
                "iframe_count": len(iframes),
            }
        except Exception as e:
            log.warning("DOM parse warning: %s", e)
            return {}

    def _compute_webpage_risk(self, signals: Dict[str, Any], cross_domain: bool, redirect_count: int) -> int:
        if not signals:
            return 0
        score = 0
        if signals.get("has_password_field"):
            score += 25
        if signals.get("has_suspicious_action"):
            score += 30
        if signals.get("has_spoofed_hyperlinks"):
            score += 40
        if signals.get("title_auth_mismatch"):
            score += 15
        if signals.get("right_click_disabled"):
            score += 12
        if signals.get("suspicious_js_count", 0) >= 2:
            score += 15
        if cross_domain and redirect_count >= 2:
            score += 15
        return min(100, score)

redirect_inspector = RedirectAndWebpageInspector()
