"""
website_audit_orchestrator.py — Complete 10-Category Website Security & Health Audit Engine
Orchestrates:
  1. Phishing Risk (PSL + Calibrated ML Ensemble)
  2. Malware & Threat Intelligence (OpenPhish + URLhaus + GSB/VT)
  3. Website Compromise Indicators (Hidden iframes, Obfuscated JS, Defacement, Forms)
  4. Technology Lifecycle & Outdated Software (Headers, Meta tags, EOL Database)
  5. Known Vulnerabilities (NVD CVE records correlated to detected versions)
  6. TLS & Certificate Security (Issuer, SANs, Expiry, Certificate Transparency)
  7. HTTP Security Configuration (HSTS, CSP, XFO, XCTO, Cookies)
  8. Domain Age & DNS Intelligence (RDAP, SPF, DMARC, DNSSEC)
  9. Deployment & Historical Observation (Web Archive, First Seen, Last Seen)
  10. Website Availability & Technical Errors (HTTP status, Latency, Broken Assets)
"""

import time
import asyncio
import logging
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional
from urllib.parse import urlparse

from redirect_inspector import redirect_inspector
from threat_reputation import threat_reputation_engine
from content_compromise_inspector import content_compromise_inspector
from domain_intelligence import domain_intelligence_engine
from certificate_history import certificate_history_engine
from tech_stack_detector import tech_stack_detector
from cve_intelligence import cve_intelligence_engine
from security_headers_evaluator import security_headers_evaluator
from website_health_inspector import website_health_inspector

log = logging.getLogger("phishsense-audit-orchestrator")

class WebsiteAuditOrchestrator:
    def __init__(self):
        pass

    async def execute_audit(self, url: str, is_owner_authorized: bool = False,
                            existing_first_seen: Optional[str] = None) -> Dict[str, Any]:
        """
        Executes a comprehensive, multi-layer website security and health audit.
        Returns 10 independently evaluated assessment categories with full technical evidence.
        """
        start_time = time.time()
        url = url.strip()
        if not url.startswith(("http://", "https://")):
            url = f"https://{url}"

        parsed = urlparse(url)
        hostname = (parsed.netloc or "").split(":")[0].lower().replace("www.", "")
        audit_timestamp = datetime.now(timezone.utc).isoformat()

        # ── 1. Fetch Page with SSRF Protection via redirect_inspector ─────────
        inspection = await redirect_inspector.inspect(url)
        final_url = inspection.get("final_url", url)
        http_status = inspection.get("http_status")
        headers = inspection.get("response_headers", {})
        html_text = inspection.get("html_content", "")
        redirect_chain = inspection.get("redirect_chain", [])
        latency_ms = inspection.get("response_time_ms", (time.time() - start_time) * 1000)

        # ── 2. Run Independent Evaluations Concurrently ───────────────────────
        reputation_task = threat_reputation_engine.evaluate_reputation(final_url)
        domain_task = domain_intelligence_engine.get_domain_intelligence(hostname)
        cert_task = certificate_history_engine.inspect_certificate_and_history(final_url, existing_first_seen)
        health_task = website_health_inspector.inspect_health(final_url, http_status, latency_ms, html_text, redirect_chain)

        # Execute parallel network tasks with safe exception gathering
        reputation_res, domain_res, cert_res, health_res = await asyncio.gather(
            reputation_task, domain_task, cert_task, health_task,
            return_exceptions=True
        )

        # Safe unpack of gathered results
        reputation_data = reputation_res if isinstance(reputation_res, dict) else {
            "status": "INSUFFICIENT_EVIDENCE", "risk_level": "LOW", "finding": "Reputation lookup encountered a network error.", "matches": []
        }
        domain_data = domain_res if isinstance(domain_res, dict) else {
            "status": "INSUFFICIENT_EVIDENCE", "risk_level": "LOW", "finding": "Domain RDAP/DNS query failed.", "registration": {}, "dns_records": {}
        }
        cert_data = cert_res if isinstance(cert_res, dict) else {
            "status": "INSUFFICIENT_EVIDENCE", "risk_level": "LOW", "findings": ["TLS inspection timed out."], "live_certificate": {}, "certificate_transparency": {}, "archive_history": {}
        }
        health_data = health_res if isinstance(health_res, dict) else {
            "status": "UNREACHABLE", "risk_level": "UNREACHABLE", "finding": "Health check timed out or host unreachable.", "broken_resources": [], "health_issues": []
        }

        # ── 3. Run In-Memory Synchronous Inspections ──────────────────────────
        compromise_data = content_compromise_inspector.inspect_content(final_url, html_text, http_status)
        tech_data = tech_stack_detector.detect_technologies(headers, html_text)
        cve_data = cve_intelligence_engine.match_vulnerabilities(tech_data.get("technologies", []))
        headers_data = security_headers_evaluator.evaluate_headers(headers, is_https=final_url.startswith("https://"))

        # ── 4. Construct the 10 Standard Assessment Categories ────────────────
        categories = []

        # Category 1: Phishing Risk
        categories.append({
            "category_id": "PHISHING_RISK",
            "category_name": "Phishing Risk & Brand Impersonation",
            "status": "HIGH" if inspection.get("webpage_risk_score", 0) > 60 else ("MEDIUM" if inspection.get("webpage_risk_score", 0) > 30 else "NO_ISSUE_DETECTED"),
            "finding": "Credential traps or brand impersonation signals detected." if inspection.get("webpage_risk_score", 0) > 50 else "No phishing or deceptive brand impersonation patterns identified.",
            "evidence": {
                "initial_url": url,
                "final_destination": final_url,
                "redirect_hops": len(redirect_chain),
                "is_cross_domain_redirect": inspection.get("cross_domain_redirect", False),
                "webpage_risk_score": inspection.get("webpage_risk_score", 0),
                "dom_signals": inspection.get("dom_signals", {})
            },
            "source": "PhishSense Brand Knowledge Base & Redirect Tracer",
            "confidence": "HIGH",
            "why_it_matters": "Phishing sites impersonate authentic brands to steal login credentials, payment details, or personal data.",
            "recommended_action": "Never enter credentials or payment details if the domain root does not match the official organization."
        })

        # Category 2: Malware & Threat Intelligence
        categories.append({
            "category_id": "MALWARE_AND_THREAT_INTEL",
            "category_name": "Malware & Threat Intelligence",
            "status": reputation_data.get("risk_level", "NO_ISSUE_DETECTED"),
            "finding": reputation_data.get("finding", "No active threat intelligence matches."),
            "evidence": {
                "is_known_threat": reputation_data.get("is_known_threat", False),
                "has_exact_url_match": reputation_data.get("has_exact_url_match", False),
                "sources_checked": reputation_data.get("sources_checked", []),
                "matches": reputation_data.get("matches", []),
                "last_feed_refresh": reputation_data.get("last_feed_refresh"),
                "coverage_disclaimer": reputation_data.get("coverage_disclaimer"),
                "licensing_notice": reputation_data.get("licensing_notice")
            },
            "source": "OpenPhish, URLhaus Community API, Google Web Risk & VirusTotal Passive Intelligence",
            "confidence": "HIGH" if reputation_data.get("is_known_threat") else "MEDIUM",
            "why_it_matters": "Domains flagged in threat databases are known to distribute malware or coordinate phishing campaigns.",
            "recommended_action": "Block access to the destination if confirmed in active threat feeds."
        })

        # Category 3: Website Compromise Indicators
        categories.append({
            "category_id": "COMPROMISE_INDICATORS",
            "category_name": "Website Content & Compromise Inspection",
            "status": compromise_data.get("risk_level", "NO_ISSUE_DETECTED"),
            "finding": compromise_data.get("finding", "No malicious compromise indicators found."),
            "evidence": {
                "inspection_mode": compromise_data.get("inspection_mode"),
                "total_indicators": compromise_data.get("total_indicators", 0),
                "indicators": compromise_data.get("indicators", []),
                "summary": compromise_data.get("summary")
            },
            "source": "Passive DOM & Script Analysis",
            "confidence": "HIGH",
            "why_it_matters": "Compromised websites frequently host hidden iframes, cryptocurrency miners, or defacement scripts without the owner's knowledge.",
            "recommended_action": "Remove unauthorized scripts, hidden iframes, or external form actions."
        })

        # Category 4: Technology Lifecycle & Outdated Software
        categories.append({
            "category_id": "TECHNOLOGY_LIFECYCLE",
            "category_name": "Technology Stack & Software Lifecycle",
            "status": tech_data.get("risk_level", "INFORMATIONAL"),
            "finding": tech_data.get("finding", "Identified website technologies."),
            "evidence": {
                "technologies": tech_data.get("technologies", []),
                "total_detected": tech_data.get("total_technologies", 0),
                "outdated_count": tech_data.get("outdated_count", 0),
                "methodology": tech_data.get("methodology")
            },
            "source": "HTTP Response Headers & Meta Generator Fingerprinting",
            "confidence": "HIGH",
            "why_it_matters": "Running End-of-Life or outdated software leaves servers vulnerable to known automated exploit kits.",
            "recommended_action": "Upgrade outdated software and frameworks to the latest supported stable release."
        })

        # Category 5: Known Vulnerabilities (CVEs)
        categories.append({
            "category_id": "KNOWN_VULNERABILITIES",
            "category_name": "CVE Vulnerability Intelligence",
            "status": cve_data.get("risk_level", "INFORMATIONAL"),
            "finding": cve_data.get("finding", "No correlated CVE matches found."),
            "evidence": {
                "potential_count": cve_data.get("potential_cve_count", 0),
                "confirmed_count": cve_data.get("confirmed_cve_count", 0),
                "total_noted": cve_data.get("total_cves_noted", 0),
                "vulnerabilities": cve_data.get("vulnerabilities", []),
                "disclaimer": cve_data.get("disclaimer")
            },
            "source": "National Vulnerability Database (NVD) Version Correlation",
            "confidence": "HIGH" if cve_data.get("potential_cve_count", 0) > 0 else "MEDIUM",
            "why_it_matters": "Known vulnerabilities (CVEs) allow attackers to exploit unpatched systems via public exploit code.",
            "recommended_action": "Patch affected software packages or apply vendor security workarounds immediately."
        })

        # Category 6: TLS & Certificates
        cert_live = cert_data.get("live_certificate", {})
        categories.append({
            "category_id": "TLS_AND_CERTIFICATES",
            "category_name": "TLS Certificate & Cryptographic Health",
            "status": cert_data.get("risk_level", "INFORMATIONAL"),
            "finding": "; ".join(cert_data.get("findings", ["TLS certificate validated."])),
            "evidence": {
                "has_tls": cert_live.get("has_tls", False),
                "issuer_org": cert_live.get("issuer_org"),
                "issuer_cn": cert_live.get("issuer_cn"),
                "not_after": cert_live.get("not_after_formatted"),
                "days_until_expiry": cert_live.get("days_until_expiry"),
                "hostname_match": cert_live.get("hostname_match", False),
                "san_list": cert_live.get("san_list", [])[:10],
                "certificate_transparency": cert_data.get("certificate_transparency", {})
            },
            "source": "Live SSL Handshake & Certificate Transparency Logs",
            "confidence": "HIGH",
            "why_it_matters": "An invalid or expired certificate breaks encrypted communication and indicates poor administrative hygiene or active MITM attacks.",
            "recommended_action": "Ensure certificates are automatically renewed at least 30 days before expiration with matching hostnames."
        })

        # Category 7: HTTP Security Configuration
        categories.append({
            "category_id": "HTTP_SECURITY_HEADERS",
            "category_name": "HTTP Security Configuration & Headers",
            "status": headers_data.get("risk_level", "MEDIUM"),
            "finding": headers_data.get("finding", "Security headers evaluated."),
            "evidence": {
                "header_checks": headers_data.get("header_checks", []),
                "cookie_checks": headers_data.get("cookie_checks", []),
                "information_disclosure": headers_data.get("information_disclosure", []),
                "missing_count": headers_data.get("missing_count", 0),
                "optimal_count": headers_data.get("optimal_count", 0)
            },
            "source": "HTTP Response Headers Inspection",
            "confidence": "HIGH",
            "why_it_matters": "Missing security headers expose web applications to Clickjacking, XSS injection, and SSL-stripping.",
            "recommended_action": "Configure HSTS, Content-Security-Policy, X-Frame-Options, and X-Content-Type-Options."
        })

        # Category 8: Domain Age & DNS Intelligence
        reg_info = domain_data.get("registration", {})
        dns_info = domain_data.get("dns_records", {})
        categories.append({
            "category_id": "DOMAIN_REGISTRATION_AND_DNS",
            "category_name": "Domain Age & DNS Intelligence",
            "status": domain_data.get("risk_level", "INFORMATIONAL"),
            "finding": domain_data.get("finding", "Domain registration and DNS records retrieved."),
            "evidence": {
                "creation_date": reg_info.get("creation_date_formatted"),
                "domain_age_days": reg_info.get("domain_age_days"),
                "expiry_date": reg_info.get("expiry_date"),
                "registrar": reg_info.get("registrar"),
                "privacy_redacted": reg_info.get("privacy_redacted", False),
                "nameservers": reg_info.get("nameservers", []),
                "has_spf": dns_info.get("has_spf", False),
                "spf_record": dns_info.get("spf_record"),
                "has_dmarc": dns_info.get("has_dmarc", False),
                "dmarc_record": dns_info.get("dmarc_record"),
                "dnssec_enabled": dns_info.get("dnssec_enabled", False),
                "a_records": dns_info.get("a_records", [])[:5]
            },
            "source": "ICANN RDAP Bootstrap & Global DNS Resolvers",
            "confidence": "HIGH",
            "why_it_matters": "Freshly registered domains are commonly used for short-lived scams. SPF and DMARC prevent email spoofing of the domain.",
            "recommended_action": "Maintain active DMARC policy (p=reject or p=quarantine) to prevent domain email spoofing."
        })

        # Category 9: Deployment & Change History
        archive_info = cert_data.get("archive_history", {})
        ct_info = cert_data.get("certificate_transparency", {})
        categories.append({
            "category_id": "DEPLOYMENT_AND_CHANGE_HISTORY",
            "category_name": "Website Observation & Change History",
            "status": "INFORMATIONAL",
            "finding": f"First observed by PhishSense: {cert_data.get('phishsense_tracking', {}).get('first_observed_utc', audit_timestamp)[:10]}." + (f" Earliest web archive snapshot: {archive_info.get('earliest_snapshot_date')}." if archive_info.get('has_historical_snapshots') else ""),
            "evidence": {
                "domain_creation_date": reg_info.get("creation_date_formatted"),
                "earliest_ssl_certificate": ct_info.get("earliest_cert_date"),
                "web_archive_first_snapshot": archive_info.get("earliest_snapshot_date"),
                "web_archive_url": archive_info.get("snapshot_url"),
                "phishsense_first_observed": cert_data.get("phishsense_tracking", {}).get("first_observed_utc"),
                "phishsense_last_observed": cert_data.get("phishsense_tracking", {}).get("last_observed_utc"),
                "authorized_hosting_integration": "Available for verified domain owners (Vercel / Render deployment APIs)" if is_owner_authorized else "Owner verification required to access private deployment logs."
            },
            "source": "Wayback Machine, Certificate Transparency & PhishSense Database",
            "confidence": "HIGH",
            "why_it_matters": "Understanding observation history establishes website maturity and tracks unexpected content replacement.",
            "recommended_action": "Owners can connect verified deployment webhooks for automated pre-deployment scanning."
        })

        # Category 10: Website Availability & Technical Errors
        categories.append({
            "category_id": "WEBSITE_HEALTH_AND_AVAILABILITY",
            "category_name": "Website Availability & Technical Health",
            "status": health_data.get("risk_level", "NO_ISSUE_DETECTED"),
            "finding": health_data.get("finding", "Website is accessible and healthy."),
            "evidence": {
                "http_status": health_data.get("http_status"),
                "latency_ms": health_data.get("latency_ms"),
                "redirect_hops": health_data.get("redirect_hops", 0),
                "broken_resources_count": health_data.get("broken_count", 0),
                "broken_resources": health_data.get("broken_resources", []),
                "health_issues": health_data.get("health_issues", [])
            },
            "source": "HTTP Protocol Probing & Sampled Resource Verification",
            "confidence": "HIGH",
            "why_it_matters": "Broken resources degrade user trust and can indicate interrupted site updates or abandoned dependencies.",
            "recommended_action": "Fix broken resource links and keep latency under 2000ms."
        })

        # ── 5. Compute Transparent Executive Posture ─────────────────────────
        # Operational connectivity failure (DNS failure, unreachable, timeout) is separated from security flaws
        is_unreachable = (not inspection.get("fetch_success", False)) or (http_status is None)

        critical_count = sum(1 for c in categories if c["status"] == "CRITICAL")
        high_count = sum(1 for c in categories if c["status"] == "HIGH")
        medium_count = sum(1 for c in categories if c["status"] == "MEDIUM")
        low_count = sum(1 for c in categories if c["status"] == "LOW")
        info_count = sum(1 for c in categories if c["status"] == "INFORMATIONAL")
        clean_count = sum(1 for c in categories if c["status"] == "NO_ISSUE_DETECTED")
        unreachable_count = sum(1 for c in categories if c["status"] == "UNREACHABLE")

        if is_unreachable:
            posture_status = "UNREACHABLE"
            posture_label = "Domain Unreachable / Scan Incomplete"
            posture_badge = "UNREACHABLE"
            posture_summary = f"Target host could not be reached over the network ({inspection.get('error_msg') or 'DNS resolution failed or connection timed out'}). Operational network failure is recorded separately from confirmed security vulnerabilities."
        else:
            # Calibrate purely on active security assessment categories
            SECURITY_CATEGORIES = {
                "PHISHING_RISK", "MALWARE_AND_THREAT_INTEL", "COMPROMISE_INDICATORS",
                "TECHNOLOGY_LIFECYCLE", "KNOWN_VULNERABILITIES", "TLS_AND_CERTIFICATES",
                "HTTP_SECURITY_HEADERS"
            }
            sec_critical = sum(1 for c in categories if c["category_id"] in SECURITY_CATEGORIES and c["status"] == "CRITICAL")
            sec_high = sum(1 for c in categories if c["category_id"] in SECURITY_CATEGORIES and c["status"] == "HIGH")
            sec_medium = sum(1 for c in categories if c["category_id"] in SECURITY_CATEGORIES and c["status"] == "MEDIUM")
            sec_low = sum(1 for c in categories if c["category_id"] in SECURITY_CATEGORIES and c["status"] == "LOW")

            if sec_critical > 0:
                posture_status = "CRITICAL_RISK"
                posture_label = "Critical Security & Malicious Risks Detected"
                posture_badge = "CRITICAL"
                posture_summary = f"Detected {sec_critical} critical security finding(s). The website displays confirmed malicious indicators, server compromise, or active phishing traps."
            elif sec_high > 0:
                posture_status = "HIGH_RISK"
                posture_label = "High Risk Findings Identified"
                posture_badge = "HIGH"
                posture_summary = f"Detected {sec_high} high-severity security issue(s) requiring immediate remediation (e.g. expired certificates, missing critical headers, or confirmed vulnerable software)."
            elif sec_medium > 0:
                posture_status = "MODERATE_RISK"
                posture_label = "Moderate Security Weaknesses"
                posture_badge = "MEDIUM"
                posture_summary = f"Detected {sec_medium} medium-severity issue(s). Website functions normally but has noticeable security configuration gaps or outdated dependencies."
            elif sec_low > 0:
                posture_status = "HEALTHY_AND_SECURE"
                posture_label = "Strong Security Posture"
                posture_badge = "LOW"
                posture_summary = "No critical, high, or moderate security flaws detected. Website adheres to modern security standards with minor optional hardening opportunities."
            else:
                posture_status = "HEALTHY_AND_SECURE"
                posture_label = "Strong Security Posture"
                posture_badge = "NO_ISSUE_DETECTED"
                posture_summary = "No critical or high-risk security flaws detected. Website adheres to modern security and availability best practices."

        execution_latency = round((time.time() - start_time) * 1000)

        return {
            "target_url": final_url,
            "target_domain": hostname,
            "audit_timestamp_utc": audit_timestamp,
            "execution_duration_ms": execution_latency,
            "assessment_mode": "OWNER_AUTHORIZED_ASSESSMENT" if is_owner_authorized else "PUBLIC_PASSIVE_ASSESSMENT",
            "executive_summary": {
                "posture_status": posture_status,
                "posture_label": posture_label,
                "posture_badge": posture_badge,
                "summary": posture_summary,
                "issue_counts": {
                    "critical": critical_count,
                    "high": high_count,
                    "medium": medium_count,
                    "low": low_count,
                    "informational": info_count,
                    "clean": clean_count,
                    "total_categories": len(categories)
                }
            },
            "categories": categories,
            "disclaimer": "This report combines multiple independent technical signals. It avoids arbitrary single-score calculations to ensure transparency and explainability."
        }

website_audit_orchestrator = WebsiteAuditOrchestrator()
