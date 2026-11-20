"""
cve_intelligence.py — CVE & Vulnerability Intelligence Module
Module 6:
  - Correlates detected software versions with National Vulnerability Database (NVD) CVE records
  - Accurate affected version range matching
  - CVSS v3 severity & official vendor advisory links
  - Strict distinction: CONFIRMED_VULNERABLE vs POTENTIALLY_AFFECTED vs UNVERIFIED_FINGERPRINT
  - Strictly non-exploitative passive vulnerability intelligence
"""

import re
import logging
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional

log = logging.getLogger("phishsense-cve-intelligence")

# Curated reference database of critical and high-impact CVEs for web components
NVD_CVE_DATABASE = [
    {
        "product": "PHP",
        "cpe_match": "php",
        "affected_versions": ["7.0.", "7.1.", "7.2.", "7.3.", "7.4.", "8.0."],
        "cve_id": "CVE-2024-4577",
        "cvss_score": 9.8,
        "severity": "CRITICAL",
        "title": "PHP CGI Argument Injection Remote Code Execution",
        "description": "A character encoding bypass flaw in PHP CGI allows unauthenticated remote attackers to execute arbitrary system code.",
        "reference": "https://nvd.nist.gov/vuln/detail/CVE-2024-4577"
    },
    {
        "product": "Apache HTTP Server",
        "cpe_match": "apache",
        "affected_versions": ["2.4.49", "2.4.50"],
        "cve_id": "CVE-2021-41773",
        "cvss_score": 7.5,
        "severity": "HIGH",
        "title": "Apache Path Traversal and File Disclosure",
        "description": "Flaw in path normalization allows attackers to map URLs to files outside the document root.",
        "reference": "https://nvd.nist.gov/vuln/detail/CVE-2021-41773"
    },
    {
        "product": "Apache HTTP Server",
        "cpe_match": "apache",
        "affected_versions": ["2.4.0", "2.4.1", "2.4.2", "2.4.3", "2.4.4", "2.4.5", "2.4.6", "2.4.7", "2.4.8", "2.4.9", "2.4.10", "2.4.20", "2.4.30", "2.4.41", "2.4.46", "2.4.48", "2.4.51", "2.4.52", "2.4.53", "2.4.54", "2.4.55", "2.4.56", "2.4.57"],
        "cve_id": "CVE-2023-31122",
        "cvss_score": 7.5,
        "severity": "HIGH",
        "title": "Apache mod_macro / mod_proxy DoS & Memory Read",
        "description": "Out-of-bounds read in mod_macro allows remote attackers to trigger denial of service.",
        "reference": "https://nvd.nist.gov/vuln/detail/CVE-2023-31122"
    },
    {
        "product": "Nginx",
        "cpe_match": "nginx",
        "affected_versions": ["1.18.", "1.19.", "1.20.", "1.21.", "1.22."],
        "cve_id": "CVE-2023-44487",
        "cvss_score": 7.5,
        "severity": "HIGH",
        "title": "HTTP/2 Rapid Reset Distributed Denial of Service",
        "description": "The HTTP/2 protocol allows a denial of service (server resource consumption) via rapid stream reset requests.",
        "reference": "https://nvd.nist.gov/vuln/detail/CVE-2023-44487"
    },
    {
        "product": "WordPress",
        "cpe_match": "wordpress",
        "affected_versions": ["5.8.", "5.9.", "6.0.", "6.1.", "6.2.", "6.3."],
        "cve_id": "CVE-2023-38000",
        "cvss_score": 6.5,
        "severity": "MEDIUM",
        "title": "WordPress Core Cross-Site Scripting (XSS)",
        "description": "Improper input sanitization allows authenticated users with contributor roles to inject persistent scripts.",
        "reference": "https://nvd.nist.gov/vuln/detail/CVE-2023-38000"
    },
    {
        "product": "jQuery",
        "cpe_match": "jquery",
        "affected_versions": ["1.", "2.", "3.0.", "3.1.", "3.2.", "3.3.", "3.4."],
        "cve_id": "CVE-2020-11022",
        "cvss_score": 6.1,
        "severity": "MEDIUM",
        "title": "jQuery XSS via htmlPrefilter",
        "description": "Passing HTML containing <option> elements from untrusted sources to jQuery DOM manipulation methods may lead to untrusted script execution.",
        "reference": "https://nvd.nist.gov/vuln/detail/CVE-2020-11022"
    },
    {
        "product": "Bootstrap",
        "cpe_match": "bootstrap",
        "affected_versions": ["3.", "4."],
        "cve_id": "CVE-2019-8331",
        "cvss_score": 6.1,
        "severity": "MEDIUM",
        "title": "Bootstrap Tooltip / Popover Data-Container XSS",
        "description": "Cross-Site Scripting vulnerability in Bootstrap Tooltip and Popover plugins when data-template or container attribute is not sanitized.",
        "reference": "https://nvd.nist.gov/vuln/detail/CVE-2019-8331"
    }
]

def is_version_affected(detected_ver: str, affected_rule: str) -> bool:
    """
    Accurately matches software versions against affected ranges without substring false positives.
    Examples:
      - '2.4.5' must NOT match '2.4.58'
      - '2.4.41' matches '2.4.41' and '2.4.41-4ubuntu3'
      - '7.4.' matches '7.4.3'
    """
    det = detected_ver.strip()
    rule = affected_rule.strip()

    if rule.endswith("."):
        return det.startswith(rule) or det == rule[:-1]

    if det == rule:
        return True

    if det.startswith(rule) and len(det) > len(rule):
        next_char = det[len(rule)]
        # Legitimate package release suffixes are separated by non-digit separators (e.g. -, +, ~, _)
        return not next_char.isdigit()

    return False


class CveIntelligenceEngine:
    def __init__(self):
        pass

    def match_vulnerabilities(self, detected_technologies: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Correlates detected technologies and confirmed versions against known NVD CVEs.
        Adheres to strict defensive security standards:
          - Passive version banners cannot prove absence of backported OS patches (Ubuntu/Debian/RHEL).
          - Findings are designated as POTENTIAL_VULNERABILITY_UNVERIFIED_PATCH rather than claiming
            unverified remote exploitability.
        """
        now_iso = datetime.now(timezone.utc).isoformat()
        cve_findings: List[Dict[str, Any]] = []

        for tech in detected_technologies:
            tech_name = tech.get("name", "").lower()
            detected_ver = tech.get("version")
            has_version = tech.get("has_version", False)

            for cve in NVD_CVE_DATABASE:
                cpe_key = cve["cpe_match"]
                if cpe_key in tech_name:
                    # Case 1: Exact version known
                    if has_version and detected_ver and detected_ver != "Technology detected, version not reliably identified":
                        # Check version prefix or match with boundary defense
                        is_match = any(is_version_affected(detected_ver, aff) for aff in cve["affected_versions"])
                        if is_match:
                            cve_findings.append({
                                "cve_id": cve["cve_id"],
                                "product": tech["name"],
                                "detected_version": detected_ver,
                                "affected_range": ", ".join(cve["affected_versions"]),
                                "cvss_score": cve["cvss_score"],
                                "severity": cve["severity"],
                                "title": cve["title"],
                                "description": cve["description"],
                                "reference_url": cve["reference"],
                                "match_status": "POTENTIAL_VULNERABILITY_UNVERIFIED_PATCH",
                                "confidence": "MEDIUM",
                                "detection_confidence": tech.get("detection_confidence", "HIGH"),
                                "installed_package_verified": False,
                                "evidence": f"Installed {tech['name']} version {detected_ver} falls within known vulnerable upstream version range.",
                                "caveat": "Passive remote inspection cannot confirm whether the OS distributor (Debian, Ubuntu, RHEL) has backported security fixes without changing the version string.",
                                "source_url": cve["reference"],
                                "last_verified_utc": now_iso
                            })
                    else:
                        # Case 2: Technology detected, version not confirmed
                        cve_findings.append({
                            "cve_id": cve["cve_id"],
                            "product": tech["name"],
                            "detected_version": "Unverified",
                            "affected_range": ", ".join(cve["affected_versions"]),
                            "cvss_score": cve["cvss_score"],
                            "severity": "INFORMATIONAL",
                            "title": cve["title"],
                            "description": cve["description"],
                            "reference_url": cve["reference"],
                            "match_status": "ADVISORY_CHECK_VERSION_UNVERIFIED",
                            "confidence": "LOW",
                            "evidence": f"{tech['name']} is used by the target website, but its exact version could not be confirmed passively.",
                            "caveat": "Software version is concealed or absent from public HTTP headers.",
                            "source_url": cve["reference"],
                            "last_verified_utc": now_iso
                        })

        # Deduplicate by CVE ID
        unique_findings = []
        seen_cves = set()
        for f in cve_findings:
            if f["cve_id"] not in seen_cves:
                seen_cves.add(f["cve_id"])
                unique_findings.append(f)

        potential_count = sum(1 for f in unique_findings if f["match_status"] == "POTENTIAL_VULNERABILITY_UNVERIFIED_PATCH")
        status = "NO_ISSUE_DETECTED"
        risk_level = "INFORMATIONAL"
        finding = "No correlated CVE version matches found."

        if potential_count > 0:
            status = "POTENTIAL_VULNERABILITIES_FOUND"
            risk_level = "HIGH" if any(f.get("cvss_score", 0) >= 7.0 for f in unique_findings if f["match_status"] == "POTENTIAL_VULNERABILITY_UNVERIFIED_PATCH") else "MEDIUM"
            finding = f"Noted {potential_count} potential vulnerability match(es) for detected software versions (unverified patch status)."
        elif len(unique_findings) > 0:
            status = "POTENTIAL_VULNERABILITIES_NOTED"
            risk_level = "INFORMATIONAL"
            finding = f"Noted {len(unique_findings)} potential advisory check(s) for detected technologies with unconfirmed versions."

        return {
            "status": status,
            "risk_level": risk_level,
            "finding": finding,
            "potential_cve_count": potential_count,
            "confirmed_cve_count": 0,  # Never falsely claim confirmed remote exploitability without active testing
            "total_cves_noted": len(unique_findings),
            "vulnerabilities": unique_findings,
            "disclaimer": "Vulnerability intelligence correlates publicly identifiable software versions against NVD CVE records. It does not execute destructive exploits and cannot verify distribution-backported security patches."
        }

cve_intelligence_engine = CveIntelligenceEngine()
