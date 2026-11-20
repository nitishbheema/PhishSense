"""
tech_stack_detector.py — Passive Technology Stack & Outdated Software Detection
Module 5:
  - Passive fingerprinting via HTTP response headers, meta tags, and script paths
  - Version extraction with confidence scoring
  - Software lifecycle and End-of-Life (EOL) analysis
  - Never guesses hidden versions or invents outdated states
"""

import re
import logging
from typing import Dict, Any, List, Optional
from bs4 import BeautifulSoup

log = logging.getLogger("phishsense-tech-stack")

# Curated reference database of major software releases and End-of-Life (EOL) thresholds
LIFECYCLE_DATABASE = {
    "php": {
        "eol_versions": ["5.", "7.0", "7.1", "7.2", "7.3", "7.4", "8.0", "8.1"],
        "latest_stable": "8.3",
        "advisory": "PHP versions prior to 8.2 have reached official End-of-Life and no longer receive security patches."
    },
    "apache": {
        "outdated_before": "2.4.58",
        "advisory": "Apache HTTP Server versions prior to 2.4.58 contain known vulnerabilities (e.g., HTTP request smuggling, mod_proxy flaws)."
    },
    "nginx": {
        "outdated_before": "1.24.0",
        "advisory": "Nginx versions prior to 1.24.0 (legacy branch) may lack recent HTTP/2 and SSL/TLS mitigations."
    },
    "wordpress": {
        "outdated_before": "6.4.0",
        "advisory": "WordPress releases prior to 6.4.0 contain known core security vulnerabilities."
    },
    "drupal": {
        "eol_versions": ["7.", "8.", "9."],
        "latest_stable": "10.2",
        "advisory": "Drupal 7, 8, and 9 have reached community End-of-Life."
    },
    "joomla": {
        "eol_versions": ["3.", "4.0", "4.1", "4.2", "4.3"],
        "latest_stable": "5.0",
        "advisory": "Joomla 3.x and early 4.x branches have reached End-of-Life."
    },
    "jquery": {
        "outdated_before": "3.5.0",
        "advisory": "jQuery versions prior to 3.5.0 are vulnerable to Cross-Site Scripting (XSS) via htmlPrefilter."
    },
    "bootstrap": {
        "outdated_before": "5.0.0",
        "advisory": "Bootstrap 3.x and 4.x contain known XSS vulnerabilities in tooltip/popover plugins."
    }
}

class TechStackDetector:
    def __init__(self):
        pass

    def detect_technologies(self, headers: Dict[str, str], html_text: str) -> Dict[str, Any]:
        """
        Passively fingerprints website technologies using response headers,
        meta tags, and resource path indicators.
        """
        technologies: List[Dict[str, Any]] = []
        soup = BeautifulSoup(html_text or "", "html.parser")
        
        # Normalize header keys to lowercase
        norm_headers = {k.lower(): v for k, v in headers.items()}
        server_header = norm_headers.get("server", "")
        x_powered_by = norm_headers.get("x-powered-by", "")

        # ── 1. Web Servers (Server Header) ────────────────────────────────────
        if "nginx" in server_header.lower():
            v = self._extract_version(r"nginx/([0-9\.]+)", server_header)
            self._add_tech(technologies, "Nginx", "Web Server", v, f"HTTP Server header: '{server_header}'", "nginx")
        elif "apache" in server_header.lower():
            v = self._extract_version(r"apache/([0-9\.]+)", server_header)
            self._add_tech(technologies, "Apache HTTP Server", "Web Server", v, f"HTTP Server header: '{server_header}'", "apache")
        elif "cloudflare" in server_header.lower():
            self._add_tech(technologies, "Cloudflare Edge", "CDN / Reverse Proxy", None, f"HTTP Server header: '{server_header}'")
        elif "caddy" in server_header.lower():
            self._add_tech(technologies, "Caddy", "Web Server", None, f"HTTP Server header: '{server_header}'")
        elif "litespeed" in server_header.lower():
            self._add_tech(technologies, "LiteSpeed", "Web Server", None, f"HTTP Server header: '{server_header}'")
        elif "microsoft-iis" in server_header.lower():
            v = self._extract_version(r"microsoft-iis/([0-9\.]+)", server_header)
            self._add_tech(technologies, "Microsoft IIS", "Web Server", v, f"HTTP Server header: '{server_header}'")

        # ── 2. Backend Runtimes & Frameworks (X-Powered-By / Cookies) ────────
        if "php" in x_powered_by.lower():
            v = self._extract_version(r"php/([0-9\.]+)", x_powered_by)
            self._add_tech(technologies, "PHP", "Programming Language", v, f"X-Powered-By header: '{x_powered_by}'", "php")
        elif "asp.net" in x_powered_by.lower():
            v = self._extract_version(r"asp\.net(?:\s+version)?:?\s*([0-9\.]+)", x_powered_by)
            self._add_tech(technologies, "ASP.NET", "Web Framework", v, f"X-Powered-By header: '{x_powered_by}'")
        elif "express" in x_powered_by.lower():
            self._add_tech(technologies, "Express.js", "Web Framework (Node.js)", None, f"X-Powered-By header: '{x_powered_by}'")

        set_cookie = norm_headers.get("set-cookie", "").lower()
        if "phpsessid" in set_cookie:
            if not any(t["name"] == "PHP" for t in technologies):
                self._add_tech(technologies, "PHP", "Programming Language", None, "Set-Cookie session name: 'PHPSESSID'", "php")
        if "laravel_session" in set_cookie or "xsrf-token" in set_cookie:
            self._add_tech(technologies, "Laravel", "PHP Framework", None, "Set-Cookie session name: 'laravel_session'")
        if "django" in set_cookie or "csrftoken" in set_cookie:
            self._add_tech(technologies, "Django", "Python Framework", None, "CSRF cookie name: 'csrftoken'")

        # ── 3. Content Management Systems (HTML Meta Generator & Paths) ───────
        meta_gen = soup.find("meta", attrs={"name": lambda n: n and n.lower() == "generator"})
        gen_content = (meta_gen.get("content") or "") if meta_gen else ""

        if "wordpress" in gen_content.lower() or "wp-content" in html_text:
            v = self._extract_version(r"wordpress\s+([0-9\.]+)", gen_content)
            if not v:
                v = self._extract_version(r"ver=([0-9\.]+)", html_text)
            self._add_tech(technologies, "WordPress", "Content Management System", v, f"Generator meta tag: '{gen_content}'" if gen_content else "wp-content asset directory path", "wordpress")

        if "drupal" in gen_content.lower() or "sites/all/modules" in html_text or "x-drupal-cache" in norm_headers:
            v = self._extract_version(r"drupal\s+([0-9\.]+)", gen_content)
            self._add_tech(technologies, "Drupal", "Content Management System", v, f"Generator meta tag / X-Drupal-Cache header", "drupal")

        if "joomla" in gen_content.lower() or "media/jui" in html_text:
            v = self._extract_version(r"joomla!\s+-\s+open\s+source\s+content\s+management\s+-\s+version\s+([0-9\.]+)", gen_content)
            self._add_tech(technologies, "Joomla", "Content Management System", v, f"Generator meta tag: '{gen_content}'", "joomla")

        # ── 4. Frontend Frameworks & Libraries (Scripts / Attributes) ─────────
        scripts = soup.find_all("script")
        script_srcs = [s.get("src") or "" for s in scripts]
        all_scripts_dump = " ".join(script_srcs).lower()

        # React / Next.js
        if "_next/static" in all_scripts_dump or soup.find(id="__next"):
            self._add_tech(technologies, "Next.js", "React Framework", None, "Next.js asset bundle structure (_next/static)")
            self._add_tech(technologies, "React", "JavaScript UI Library", None, "React DOM container (__next)")
        elif "react" in all_scripts_dump:
            self._add_tech(technologies, "React", "JavaScript UI Library", None, "React script bundle path")

        # Vue.js / Nuxt
        if "_nuxt" in all_scripts_dump or soup.find(id="__nuxt"):
            self._add_tech(technologies, "Nuxt.js", "Vue Framework", None, "Nuxt.js asset bundle structure (_nuxt)")
            self._add_tech(technologies, "Vue.js", "JavaScript Framework", None, "Nuxt Vue runtime")
        elif "vue" in all_scripts_dump:
            self._add_tech(technologies, "Vue.js", "JavaScript Framework", None, "Vue script bundle path")

        # Angular
        if soup.find(attrs={"ng-version": True}) or "angular" in all_scripts_dump:
            ng_elem = soup.find(attrs={"ng-version": True})
            v = ng_elem.get("ng-version") if ng_elem else None
            self._add_tech(technologies, "Angular", "JavaScript Framework", v, f"Root element ng-version attribute: '{v}'" if v else "Angular script bundle")

        # jQuery
        for src in script_srcs:
            if "jquery" in src.lower():
                v = self._extract_version(r"jquery[.-]([0-9\.]+)", src)
                if not v:
                    v = self._extract_version(r"v=([0-9\.]+)", src)
                self._add_tech(technologies, "jQuery", "JavaScript Library", v, f"Script asset: '{src[:80]}'", "jquery")
                break

        # Bootstrap
        for link in soup.find_all("link", rel="stylesheet"):
            href = link.get("href") or ""
            if "bootstrap" in href.lower():
                v = self._extract_version(r"bootstrap[.-]([0-9\.]+)", href)
                self._add_tech(technologies, "Bootstrap", "CSS Framework", v, f"Stylesheet link: '{href[:80]}'", "bootstrap")
                break

        outdated_count = sum(1 for t in technologies if t.get("is_outdated"))
        status = "NO_ISSUE_DETECTED"
        risk_level = "INFORMATIONAL"
        finding = f"Detected {len(technologies)} software components."

        if outdated_count > 0:
            status = "OUTDATED_SOFTWARE_DETECTED"
            risk_level = "MEDIUM"
            finding = f"Detected {outdated_count} potentially outdated or End-of-Life software component(s)."

        return {
            "status": status,
            "risk_level": risk_level,
            "finding": finding,
            "total_technologies": len(technologies),
            "outdated_count": outdated_count,
            "technologies": technologies,
            "methodology": "Passive fingerprinting via HTTP response headers, meta generator tags, and public asset paths."
        }

    def _extract_version(self, pattern: str, text: str) -> Optional[str]:
        if not text:
            return None
        match = re.search(pattern, text, re.IGNORECASE)
        if match:
            return match.group(1).strip()
        return None

    def _add_tech(self, tech_list: List[Dict[str, Any]], name: str, category: str,
                  version: Optional[str], evidence: str, db_key: Optional[str] = None):
        if any(t["name"].lower() == name.lower() for t in tech_list):
            return  # avoid duplicate entries

        source_type = "REMOTE_HTTP_BANNER" if "header" in evidence.lower() else ("META_GENERATOR_TAG" if "meta" in evidence.lower() else "ASSET_SCRIPT_PATH")
        entry = {
            "name": name,
            "category": category,
            "version": version if version else "Technology detected, version not reliably identified",
            "has_version": bool(version),
            "version_confidence": "HIGH" if version else "UNKNOWN",
            "detection_confidence": "HIGH" if ("header" in evidence.lower() or "meta" in evidence.lower()) else "MEDIUM",
            "evidence": evidence,
            "source_type": source_type,
            "installed_package_verified": False,
            "backport_disclaimer": "Version extracted from public HTTP banner or asset path. Does not verify OS-backported vendor patches (e.g. Debian/Ubuntu/RHEL).",
            "lifecycle_status": "SUPPORTED",
            "is_outdated": False,
            "advisory": None
        }

        # Lifecycle & EOL Evaluation
        if db_key and db_key in LIFECYCLE_DATABASE and version:
            meta = LIFECYCLE_DATABASE[db_key]
            # Check EOL prefix match
            if "eol_versions" in meta:
                if any(version.startswith(v) for v in meta["eol_versions"]):
                    entry["lifecycle_status"] = "END_OF_LIFE"
                    entry["is_outdated"] = True
                    entry["advisory"] = meta["advisory"]
            # Check version comparison
            if "outdated_before" in meta and not entry["is_outdated"]:
                try:
                    v_parts = [int(p) for p in re.findall(r"\d+", version)[:3]]
                    target_parts = [int(p) for p in re.findall(r"\d+", meta["outdated_before"])[:3]]
                    if v_parts < target_parts:
                        entry["lifecycle_status"] = "OUTDATED"
                        entry["is_outdated"] = True
                        entry["advisory"] = meta["advisory"]
                except Exception:
                    pass

        tech_list.append(entry)

tech_stack_detector = TechStackDetector()
