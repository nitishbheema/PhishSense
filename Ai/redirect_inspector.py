"""
redirect_inspector.py — SSRF-Protected Multi-Hop Redirect Tracer and Safe Live Webpage Inspector

Security protections:
  1. Strict scheme whitelisting (HTTP, HTTPS only).
  2. Embedded credential rejection (user:pass@host).
  3. Pre-flight DNS resolution with comprehensive IP blocking:
     - Loopback (127.0.0.0/8, ::1)
     - Private networks (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, fc00::/7)
     - Link-local & cloud metadata (169.254.0.0/16, fe80::/10, 169.254.169.254)
     - Multicast, reserved, and unspecified addresses (0.0.0.0, ::)
     - Disallowed hostname patterns (localhost, *.local, *.internal)
  4. Hop-by-hop manual redirect verification (follow_redirects=False).
     Every redirect target is fully validated BEFORE connection.
  5. TLS certificate verification enabled (verify=True).
  6. Response size and execution timeout enforcement.
"""

import re
import socket
import ipaddress
import logging
from typing import Dict, Any, List, Tuple, Optional
from urllib.parse import urlparse, urljoin
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

CLOUD_METADATA_IPS = {
    "169.254.169.254",  # AWS, GCP, Azure, OpenStack
    "169.254.169.250",
    "100.100.100.200",  # Alibaba Cloud
}

DISALLOWED_HOSTS = {
    "localhost", "localhost.localdomain", "ip6-localhost", "ip6-loopback",
    "metadata.google.internal", "instance-data", "metadata"
}


def is_ip_disallowed(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> Tuple[bool, str]:
    """Check whether an IP address is private, loopback, link-local, multicast, or cloud metadata."""
    ip_str = str(ip)

    if ip_str in CLOUD_METADATA_IPS:
        return True, f"Blocked cloud metadata IP address: {ip_str}"

    if ip.is_loopback:
        return True, f"Blocked loopback address: {ip_str}"

    if ip.is_private:
        return True, f"Blocked private RFC-1918/RFC-4193 address: {ip_str}"

    if ip.is_link_local:
        return True, f"Blocked link-local address: {ip_str}"

    if ip.is_multicast:
        return True, f"Blocked multicast address: {ip_str}"

    if ip.is_reserved:
        return True, f"Blocked reserved address: {ip_str}"

    if ip.is_unspecified:
        return True, f"Blocked unspecified address: {ip_str}"

    # IPv4-mapped IPv6 check (e.g. ::ffff:127.0.0.1)
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        return is_ip_disallowed(ip.ipv4_mapped)

    return False, ""


def validate_target_url(raw_url: str) -> Tuple[bool, str, Optional[str], Optional[str]]:
    """
    Validates a URL destination for SSRF safety.
    Returns: (is_safe, error_or_ok_msg, normalized_url, hostname)
    """
    if not raw_url or not isinstance(raw_url, str):
        return False, "URL is empty or invalid", None, None

    url = raw_url.strip()
    if "://" in url:
        scheme_cand = url.split("://", 1)[0].lower()
        if scheme_cand not in ("http", "https"):
            return False, f"Invalid scheme '{scheme_cand}': only HTTP and HTTPS are permitted", None, None
    elif not url.startswith(("http://", "https://")):
        url = "http://" + url

    try:
        parsed = urlparse(url)
    except Exception as e:
        return False, f"Malformed URL: {e}", None, None

    # 1. Scheme check
    if parsed.scheme.lower() not in ("http", "https"):
        return False, f"Invalid scheme '{parsed.scheme}': only HTTP and HTTPS are permitted", None, None

    # 2. Reject embedded credentials
    if parsed.username or parsed.password:
        return False, "URLs with embedded credentials (user:pass@host) are forbidden", None, None

    # 3. Hostname check
    hostname = parsed.hostname
    if not hostname:
        return False, "URL is missing a valid hostname", None, None

    hostname_clean = hostname.lower().strip(".")

    # Disallow known local/metadata hostnames
    if hostname_clean in DISALLOWED_HOSTS or hostname_clean.endswith((".localhost", ".local", ".internal")):
        return False, f"Blocked destination hostname: '{hostname_clean}'", None, None

    # 4. If hostname is already a raw IP literal
    try:
        # Strip square brackets for IPv6
        ip_cand = hostname_clean.strip("[]")
        ip_obj = ipaddress.ip_address(ip_cand)
        disallowed, reason = is_ip_disallowed(ip_obj)
        if disallowed:
            return False, reason, None, None
        return True, "OK", url, hostname_clean
    except ValueError:
        # Not a raw IP; proceed to DNS resolution
        pass

    # 5. Pre-flight DNS resolution & IP check
    try:
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        addr_info = socket.getaddrinfo(hostname_clean, port, socket.AF_UNSPEC, socket.SOCK_STREAM)
        if not addr_info:
            return False, f"Could not resolve host: {hostname_clean}", None, None

        for item in addr_info:
            sockaddr = item[4]
            ip_str = sockaddr[0]
            try:
                ip_obj = ipaddress.ip_address(ip_str)
                disallowed, reason = is_ip_disallowed(ip_obj)
                if disallowed:
                    return False, f"DNS resolution blocked: {hostname_clean} resolves to {reason}", None, None
            except ValueError:
                return False, f"Invalid resolved IP '{ip_str}'", None, None

    except socket.gaierror as e:
        return False, f"DNS lookup failed for '{hostname_clean}': {e}", None, None
    except Exception as e:
        return False, f"Host validation error for '{hostname_clean}': {e}", None, None

    return True, "OK", url, hostname_clean


class RedirectAndWebpageInspector:
    def __init__(self, timeout: float = 4.0, max_hops: int = 5):
        self.timeout = timeout
        self.max_hops = max_hops
        self.headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 PhishSense-Auditor/4.0",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
        }

    async def inspect(self, initial_url: str) -> Dict[str, Any]:
        """
        Safely inspects a URL and its redirect chain with comprehensive SSRF protection.
        Does NOT use automatic redirect following; every hop is validated before connecting.
        """
        is_safe, msg, norm_url, initial_domain = validate_target_url(initial_url)
        if not is_safe:
            log.warning("[SSRF Defense] Rejected initial URL '%s': %s", initial_url, msg)
            return {
                "fetch_success": False,
                "error_msg": f"Security validation failed: {msg}",
                "initial_url": initial_url,
                "final_url": initial_url,
                "initial_domain": initial_domain or "unresolved",
                "final_domain": initial_domain or "unresolved",
                "http_status": None,
                "redirect_count": 0,
                "cross_domain_redirect": False,
                "redirect_chain": [],
                "dom_signals": {},
                "webpage_risk_score": 0,
                "ssrf_blocked": True,
            }

        chain: List[Dict[str, Any]] = []
        html_content = ""
        response_headers: Dict[str, str] = {}
        current_url = norm_url
        final_url = norm_url
        final_status = None
        fetch_success = False
        error_msg = None
        current_domain = initial_domain

        try:
            # We enforce follow_redirects=False to manually inspect every hop before sending requests.
            # verify=True ensures valid TLS certificates.
            async with httpx.AsyncClient(
                timeout=httpx.Timeout(self.timeout, connect=2.5),
                follow_redirects=False,
                headers=self.headers,
                verify=True,
            ) as client:

                for hop_idx in range(self.max_hops + 1):
                    # Validate current hop before making outbound request
                    hop_safe, hop_msg, validated_hop_url, hop_domain = validate_target_url(current_url)
                    if not hop_safe:
                        error_msg = f"SSRF Protection: Redirect hop {hop_idx} blocked ({hop_msg})"
                        log.warning("[SSRF Defense] Hop %d blocked for '%s': %s", hop_idx, current_url, hop_msg)
                        chain.append({
                            "hop": hop_idx,
                            "url": current_url,
                            "status": "BLOCKED_SSRF",
                            "domain": hop_domain or "unknown",
                            "blocked_reason": hop_msg,
                        })
                        break

                    current_domain = hop_domain
                    try:
                        resp = await client.get(validated_hop_url)
                    except httpx.TimeoutException:
                        error_msg = "Connection timed out during live inspection"
                        break
                    except httpx.ConnectError as ce:
                        error_msg = f"Connection failed (unreachable/refused): {str(ce)[:80]}"
                        break
                    except Exception as ex:
                        error_msg = f"Inspection request failed: {str(ex)[:80]}"
                        break

                    chain.append({
                        "hop": hop_idx,
                        "url": validated_hop_url,
                        "status": resp.status_code,
                        "domain": hop_domain.replace("www.", "") if hop_domain else "unknown",
                    })

                    # Handle HTTP redirects (301, 302, 303, 307, 308)
                    if resp.is_redirect:
                        loc = resp.headers.get("location")
                        if not loc:
                            error_msg = "Redirect header missing Location target"
                            break
                        # Join relative redirect location to base
                        current_url = urljoin(validated_hop_url, loc.strip())
                        continue
                    else:
                        # Reached terminal endpoint
                        final_url = validated_hop_url
                        final_status = resp.status_code
                        fetch_success = True
                        html_content = resp.text[:300_000]
                        response_headers = dict(resp.headers)
                        break

        except Exception as ex:
            error_msg = f"Live inspection encountered unexpected error: {str(ex)[:80]}"

        final_domain = urlparse(final_url).netloc.lower().split(":")[0].replace("www.", "") if final_url else initial_domain
        redirect_count = max(0, len(chain) - 1)
        cross_domain = (initial_domain != final_domain) if (fetch_success and redirect_count > 0) else False

        dom_signals = self._analyze_dom(final_url, final_domain, html_content) if fetch_success else {}
        webpage_risk = self._compute_webpage_risk(dom_signals, cross_domain, redirect_count)

        return {
            "fetch_success": fetch_success,
            "error_msg": error_msg,
            "initial_url": initial_url,
            "final_url": final_url,
            "initial_domain": initial_domain,
            "final_domain": final_domain,
            "http_status": final_status,
            "html_content": html_content,
            "response_headers": response_headers,
            "redirect_count": redirect_count,
            "cross_domain_redirect": cross_domain,
            "redirect_chain": chain,
            "dom_signals": dom_signals,
            "webpage_risk_score": webpage_risk,
            "ssrf_blocked": "SSRF Protection" in str(error_msg),
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
                if disp.lower().startswith(("http://", "https://", "www.")) or re.match(
                    r"^[a-zA-Z0-9-]+\.(com|org|net|edu|gov|io|co|in|xyz|app|dev|me|info)(/[^\s]*)?$",
                    disp, re.IGNORECASE
                ):
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
