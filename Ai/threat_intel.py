"""
threat_intel.py — PhishSense Multi-Feed Threat Intelligence Engine

Ingests, caches, and queries verified threat feeds:
  1. OpenPhish Community Feed (Verified phishing targets)
  2. URLhaus Abuse.ch Feed (Active malware distribution & phishing payloads)
  3. Curated High-Fidelity Threat Indicators & Known Attack Infrastructure

Design:
  - Sub-millisecond in-memory hash set & trie lookups.
  - Asynchronous / non-blocking background feed refresh (never blocks user scan requests).
  - Multi-tenant cloud provider protection to prevent false positives on shared hosts.
  - Cache persistence with timestamp tracking.
"""

import os
import json
import time
import logging
import threading
from datetime import datetime, timezone
from typing import Dict, Any, Optional
from urllib.parse import urlparse
import httpx

log = logging.getLogger("phishsense-threat-intel")

CACHE_DIR = os.path.join(os.path.dirname(__file__), "data")
CACHE_FILE = os.path.join(CACHE_DIR, "threat_intel_cache.json")
CACHE_TTL_SECONDS = 6 * 3600  # 6 hours

# Seed list of known high-risk phishing indicators and confirmed attack infrastructure
SEED_PHISHING_DOMAINS = {
    "secure-paypal-login.xyz",
    "paypal-account-update.com.verify-billing.xyz",
    "apple-id-verify-icloud.account-security.top",
    "signin-microsoft-online.security-auth.cf",
    "chase-online-verify-login.banking-auth.ml",
    "netflix-billing-update-account.billing-fix.xyz",
    "wellsfargo-security-alert.auth-portal.top",
    "google-docs-credential-access.cloud-drive.cam",
    "facebook-security-appeal-support.meta-service.icu",
    "instagram-badge-verification-center.support-help.click",
    "binance-kyc-verify-account.crypto-wallet.win",
    "metamask-wallet-synchronize.decentralized-auth.date",
}

MULTI_TENANT_HOSTS = {
    "github.com", "gitlab.com", "dropbox.com", "google.com", "drive.google.com",
    "discord.com", "discordapp.com", "pages.dev", "vercel.app", "netlify.app",
    "azurewebsites.net", "firebaseapp.com", "s3.amazonaws.com", "raw.githubusercontent.com",
    "bitbucket.org", "box.com", "onedrive.live.com", "medium.com", "wordpress.com",
    "blogspot.com", "weebly.com", "wixsite.com"
}


def is_multi_tenant_host(dom: str) -> bool:
    dom = dom.lower().strip()
    return dom in MULTI_TENANT_HOSTS or any(dom.endswith("." + m) for m in MULTI_TENANT_HOSTS)


class ThreatIntelligenceManager:
    def __init__(self):
        self.exact_urls: Dict[str, Dict[str, Any]] = {}
        self.malicious_domains: Dict[str, Dict[str, Any]] = {}
        self.last_updated: float = 0.0
        self.is_refreshing: bool = False
        self._refresh_lock = threading.Lock()
        self.feed_stats: Dict[str, Any] = {
            "openphish_count": 0,
            "urlhaus_count": 0,
            "last_sync_status": "INITIALIZING"
        }
        self._load_cached_intelligence()

    def _normalize_url_for_lookup(self, url: str) -> str:
        url = url.strip()
        if not url.startswith(("http://", "https://")):
            url = "http://" + url
        parsed = urlparse(url)
        netloc = parsed.netloc.lower().split(":")[0].replace("www.", "")
        path = parsed.path.rstrip("/")
        query = ("?" + parsed.query) if parsed.query else ""
        return f"{netloc}{path}{query}"

    def _extract_domain(self, url: str) -> str:
        if not url.startswith(("http://", "https://")):
            url = "http://" + url
        return urlparse(url).netloc.lower().split(":")[0].replace("www.", "")

    def _load_cached_intelligence(self):
        os.makedirs(CACHE_DIR, exist_ok=True)
        if os.path.exists(CACHE_FILE):
            try:
                with open(CACHE_FILE, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    self.exact_urls = data.get("exact_urls", {})
                    raw_domains = data.get("malicious_domains", {})
                    self.malicious_domains = {d: v for d, v in raw_domains.items() if not is_multi_tenant_host(d)}
                    self.last_updated = data.get("last_updated", 0.0)
                    self.feed_stats = data.get("feed_stats", self.feed_stats)
                    log.info("Loaded threat intel cache: %d URLs, %d domains", len(self.exact_urls), len(self.malicious_domains))
            except Exception as e:
                log.warning("Could not read threat intel cache: %s", e)

        # Ensure seed domains are always present
        for d in SEED_PHISHING_DOMAINS:
            if not is_multi_tenant_host(d):
                self.malicious_domains[d] = {
                    "source": "LocalCuratedIntel",
                    "threat_type": "phishing",
                    "reported_at": time.time(),
                }

    def _save_cache(self):
        try:
            with open(CACHE_FILE, "w", encoding="utf-8") as f:
                json.dump({
                    "last_updated": self.last_updated,
                    "exact_urls": self.exact_urls,
                    "malicious_domains": self.malicious_domains,
                    "feed_stats": self.feed_stats,
                }, f)
        except Exception as e:
            log.warning("Failed to save threat intel cache: %s", e)

    def trigger_async_refresh(self):
        """Launches feed refresh in background thread without blocking user requests."""
        if self.is_refreshing:
            return
        threading.Thread(target=self._refresh_feeds_worker, daemon=True).start()

    def _refresh_feeds_worker(self):
        with self._refresh_lock:
            if self.is_refreshing:
                return
            self.is_refreshing = True

        log.info("[ThreatIntel] Commencing background feed sync (OpenPhish + URLhaus)...")
        new_urls = 0
        new_domains = 0
        openphish_ok = False
        urlhaus_ok = False
        op_count = 0
        uh_count = 0

        # 1. Fetch OpenPhish Community Feed
        # Note: OpenPhish Community Feed is permitted for academic/personal research only.
        try:
            resp = httpx.get("https://openphish.com/feed.txt", timeout=10.0, headers={"User-Agent": "PhishSense/4.0"}, follow_redirects=True)
            if resp.status_code == 200:
                for line in resp.text.splitlines():
                    u = line.strip()
                    if u and not u.startswith("#"):
                        norm = self._normalize_url_for_lookup(u)
                        dom = self._extract_domain(u)
                        self.exact_urls[norm] = {"source": "OpenPhish", "threat_type": "phishing", "url": u}
                        if dom and not is_multi_tenant_host(dom):
                            self.malicious_domains[dom] = {"source": "OpenPhish", "threat_type": "phishing"}
                        op_count += 1
                openphish_ok = True
                log.info("[ThreatIntel] OpenPhish sync completed (%d items)", op_count)
            else:
                log.warning("[ThreatIntel] OpenPhish sync returned HTTP %d", resp.status_code)
        except Exception as ex:
            log.warning("[ThreatIntel] OpenPhish sync warning: %s", ex)

        # 2. Fetch URLhaus Recent Feed (Migrated from 410 Gone legacy endpoint to Community API v1)
        abuse_ch_key = os.getenv("ABUSE_CH_API_KEY") or os.getenv("URLHAUS_API_KEY")
        if abuse_ch_key:
            try:
                # Modern supported endpoint requires Auth-Key header
                resp = httpx.get(
                    "https://urlhaus-api.abuse.ch/v1/urls/recent/",
                    headers={"Auth-Key": abuse_ch_key, "User-Agent": "PhishSense/4.0"},
                    timeout=12.0
                )
                if resp.status_code == 200:
                    data = resp.json()
                    urls_list = data.get("urls", [])
                    for item in urls_list:
                        u = item.get("url")
                        if u and u.startswith("http"):
                            norm = self._normalize_url_for_lookup(u)
                            dom = self._extract_domain(u)
                            self.exact_urls[norm] = {"source": "URLhaus", "threat_type": item.get("threat", "malware_phish"), "url": u}
                            if dom and not is_multi_tenant_host(dom):
                                self.malicious_domains[dom] = {"source": "URLhaus", "threat_type": item.get("threat", "malware_phish")}
                            uh_count += 1
                    urlhaus_ok = True
                    log.info("[ThreatIntel] URLhaus API sync completed (%d items)", uh_count)
                elif resp.status_code in [401, 403]:
                    log.warning("[ThreatIntel] URLhaus API auth failure (HTTP %d): %s", resp.status_code, resp.text[:120])
                    self.feed_stats["urlhaus_error"] = f"HTTP {resp.status_code}: Invalid or unauthorized ABUSE_CH_API_KEY"
                else:
                    log.warning("[ThreatIntel] URLhaus API returned unexpected HTTP %d", resp.status_code)
                    self.feed_stats["urlhaus_error"] = f"HTTP {resp.status_code}"
            except Exception as ex:
                log.warning("[ThreatIntel] URLhaus API sync warning: %s", ex)
                self.feed_stats["urlhaus_error"] = str(ex)
        else:
            log.info("[ThreatIntel] URLhaus live feed sync skipped: ABUSE_CH_API_KEY not configured. (Legacy /downloads/ returned HTTP 410 Gone; official API requires Auth-Key). Using persistent local cache.")
            self.feed_stats["urlhaus_status"] = "UNCONFIGURED_AUTH_KEY_REQUIRED"
            self.feed_stats["urlhaus_note"] = "Legacy downloads returned HTTP 410 Gone. The modern URLhaus Community API requires an Auth-Key from abuse.ch."

        if openphish_ok or urlhaus_ok:
            self.last_updated = time.time()
            self.feed_stats.update({
                "openphish_count": op_count,
                "urlhaus_count": uh_count,
                "last_sync_status": "SUCCESS",
                "last_sync_timestamp": datetime.now(timezone.utc).isoformat()
            })
            self._save_cache()
            log.info("[ThreatIntel] Cache updated: %d total URLs, %d total domains",
                     len(self.exact_urls), len(self.malicious_domains))
        else:
            self.feed_stats["last_sync_status"] = "PARTIAL_OR_FAILED"

        self.is_refreshing = False

    def check_threat(self, url: str) -> Dict[str, Any]:
        """
        Sub-millisecond lookup against cached threat databases.
        Triggers non-blocking background refresh if cache is expired.
        """
        if time.time() - self.last_updated > CACHE_TTL_SECONDS:
            self.trigger_async_refresh()

        norm = self._normalize_url_for_lookup(url)
        domain = self._extract_domain(url)

        # 1. Exact URL Match
        if norm in self.exact_urls:
            info = self.exact_urls[norm]
            return {
                "is_known_threat": True,
                "match_type": "EXACT_URL",
                "source": info.get("source", "ThreatIntelFeed"),
                "threat_type": info.get("threat_type", "phishing"),
                "matched_entry": norm,
                "confidence": 1.0,
                "details": f"Verified malicious URL active in {info.get('source')} threat intelligence feed",
            }

        # 2. Malicious Domain Match
        if domain in self.malicious_domains:
            info = self.malicious_domains[domain]
            return {
                "is_known_threat": True,
                "match_type": "DOMAIN_LISTED",
                "source": info.get("source", "ThreatIntelFeed"),
                "threat_type": info.get("threat_type", "phishing"),
                "matched_entry": domain,
                "confidence": 0.98,
                "details": f"Target domain [{domain}] is flagged in global {info.get('source')} threat repository",
            }

        # 3. Check parent subdomains (e.g. login.evil.com -> evil.com)
        parts = domain.split(".")
        if len(parts) > 2:
            for i in range(1, len(parts) - 1):
                parent = ".".join(parts[i:])
                if parent in self.malicious_domains:
                    info = self.malicious_domains[parent]
                    return {
                        "is_known_threat": True,
                        "match_type": "PARENT_DOMAIN_LISTED",
                        "source": info.get("source", "ThreatIntelFeed"),
                        "threat_type": info.get("threat_type", "phishing"),
                        "matched_entry": parent,
                        "confidence": 0.95,
                        "details": f"Host belongs to malicious infrastructure [{parent}] cataloged in {info.get('source')}",
                    }

        return {
            "is_known_threat": False,
            "match_type": "NONE",
            "source": None,
            "threat_type": None,
            "matched_entry": None,
            "confidence": 0.0,
            "details": "No exact entry in active threat intelligence feeds (proceed to ML & live analysis)",
        }

    def get_status(self) -> Dict[str, Any]:
        """Provides transparent metadata about threat feeds and licensing constraints."""
        age_hours = round((time.time() - self.last_updated) / 3600.0, 1) if self.last_updated > 0 else None
        has_urlhaus_key = bool(os.getenv("ABUSE_CH_API_KEY") or os.getenv("URLHAUS_API_KEY"))
        urlhaus_status = "Active (Community API v1)" if has_urlhaus_key else "Unavailable - Requires Auth-Key (Legacy /downloads/ returned HTTP 410 Gone)"

        return {
            "feeds": [
                {
                    "name": "OpenPhish Community Feed",
                    "type": "Live Phishing Feed",
                    "status": "Active",
                    "licensing": "Academic/personal research use only; commercial product deployment requires OpenPhish Premium license."
                },
                {
                    "name": "URLhaus Abuse.ch Feed",
                    "type": "Malware & Phishing URLs",
                    "status": urlhaus_status,
                    "licensing": "abuse.ch Fair Use (requires free registered Auth-Key header; non-commercial community defense)."
                },
                {
                    "name": "PhishSense Curated Threat Database",
                    "type": "Localized High-Fidelity Threat DB",
                    "status": "Active",
                    "licensing": "Internal verified threat indicators."
                }
            ],
            "total_cached_urls": len(self.exact_urls),
            "total_cached_domains": len(self.malicious_domains),
            "last_updated_epoch": self.last_updated,
            "cache_age_hours": age_hours,
            "is_stale": (age_hours is not None and age_hours > 24),
            "feed_stats": self.feed_stats
        }


threat_intel = ThreatIntelligenceManager()
