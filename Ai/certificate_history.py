"""
certificate_history.py — TLS Certificate Intelligence & Website Observation History
Module 4:
  - Live TLS Certificate parsing (SANs, Issuer, Expiry, Hostname matching)
  - Certificate Transparency (CT) log query (Earliest observed certificate date)
  - Public Web Archive history lookup (Wayback Machine snapshot dates)
  - Internal PhishSense observation timestamps
  - Explicit distinction between certificate issuance and code deployment
"""

import ssl
import socket
import logging
import httpx
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional
from urllib.parse import urlparse

log = logging.getLogger("phishsense-certificate-history")

class CertificateHistoryEngine:
    def __init__(self):
        self.timeout = 4.0

    async def inspect_certificate_and_history(self, url: str, existing_first_seen: Optional[str] = None) -> Dict[str, Any]:
        """
        Inspects live TLS certificate, queries Certificate Transparency logs,
        and retrieves public web archive history.
        """
        parsed = urlparse(url)
        hostname = (parsed.netloc or "").split(":")[0].lower()
        port = parsed.port or (443 if parsed.scheme.lower() == "https" else 80)

        # 1. Inspect Live TLS Certificate
        live_cert = self._get_live_tls_certificate(hostname, port if port != 80 else 443)

        # 2. Query Certificate Transparency (CT) Logs for Earliest Issuance
        ct_data = await self._query_certificate_transparency(hostname)

        # 3. Query Public Web Archive (Wayback Machine)
        archive_data = await self._query_web_archive(url)

        # 4. Synthesize Timeline & Findings
        status = "NO_ISSUE_DETECTED"
        risk_level = "INFORMATIONAL"
        findings = []

        if not live_cert.get("has_tls"):
            status = "NO_TLS_CERTIFICATE"
            risk_level = "HIGH"
            findings.append("No active TLS certificate found. Website served over unencrypted HTTP.")
        else:
            if live_cert.get("is_expired"):
                status = "CERTIFICATE_EXPIRED"
                risk_level = "HIGH"
                findings.append(f"TLS certificate expired on {live_cert.get('not_after_formatted')}.")
            elif live_cert.get("days_until_expiry", 100) < 14:
                status = "CERTIFICATE_EXPIRING_SOON"
                risk_level = "MEDIUM"
                findings.append(f"TLS certificate expires in {live_cert.get('days_until_expiry')} days.")
            elif not live_cert.get("hostname_match"):
                status = "HOSTNAME_MISMATCH"
                risk_level = "HIGH"
                findings.append(f"Certificate hostname mismatch: Hostname '{hostname}' does not match certificate SAN list.")
            else:
                findings.append(f"Valid TLS certificate issued by '{live_cert.get('issuer_org', 'Trusted CA')}'.")

        now_iso = datetime.now(timezone.utc).isoformat()
        first_seen_val = existing_first_seen or now_iso

        return {
            "hostname": hostname,
            "status": status,
            "risk_level": risk_level,
            "findings": findings,
            "live_certificate": live_cert,
            "certificate_transparency": ct_data,
            "archive_history": archive_data,
            "phishsense_tracking": {
                "first_observed_utc": first_seen_val,
                "last_observed_utc": now_iso,
                "observation_source": "PhishSense Continuous Threat Scanner"
            },
            "timeline_summary": {
                "earliest_cert_observed": ct_data.get("earliest_cert_date"),
                "archive_first_snapshot": archive_data.get("earliest_snapshot_date"),
                "phishsense_first_seen": first_seen_val,
                "phishsense_last_seen": now_iso
            },
            "disclaimer": "Certificate issuance history reflects SSL certificate creation, which is independent of code deployment dates. Authoritative deployment logs require owner credentials."
        }

    def _get_live_tls_certificate(self, hostname: str, port: int = 443) -> Dict[str, Any]:
        cert_info = {
            "has_tls": False,
            "issuer_cn": None,
            "issuer_org": None,
            "subject_cn": None,
            "san_list": [],
            "not_before": None,
            "not_after": None,
            "not_after_formatted": None,
            "days_until_expiry": None,
            "is_expired": False,
            "hostname_match": False,
            "version": None,
            "signature_algorithm": None,
        }

        try:
            ctx = ssl.create_default_context()
            ctx.timeout = self.timeout
            with socket.create_connection((hostname, port), timeout=self.timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    cert_info["has_tls"] = True

                    # Issuer
                    for item in cert.get("issuer", []):
                        for k, v in item:
                            if k == "commonName":
                                cert_info["issuer_cn"] = v
                            elif k == "organizationName":
                                cert_info["issuer_org"] = v

                    # Subject
                    for item in cert.get("subject", []):
                        for k, v in item:
                            if k == "commonName":
                                cert_info["subject_cn"] = v

                    # Subject Alternative Names (SANs)
                    sans = []
                    for k, v in cert.get("subjectAltName", []):
                        if k.lower() == "dns":
                            sans.append(v.lower())
                    cert_info["san_list"] = sans

                    # Hostname match check
                    h_lower = hostname.lower()
                    match_found = False
                    for san in sans:
                        if san == h_lower:
                            match_found = True
                            break
                        if san.startswith("*.") and h_lower.endswith(san[1:]):
                            match_found = True
                            break
                    if not match_found and cert_info["subject_cn"] and cert_info["subject_cn"].lower() == h_lower:
                        match_found = True
                    cert_info["hostname_match"] = match_found

                    # Dates
                    nb_str = cert.get("notBefore")
                    na_str = cert.get("notAfter")
                    now_utc = datetime.now(timezone.utc)

                    if nb_str:
                        # Format: 'May 10 00:00:00 2024 GMT'
                        try:
                            nb_dt = datetime.strptime(nb_str, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                            cert_info["not_before"] = nb_dt.isoformat()
                        except Exception:
                            cert_info["not_before"] = nb_str

                    if na_str:
                        try:
                            na_dt = datetime.strptime(na_str, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                            cert_info["not_after"] = na_dt.isoformat()
                            cert_info["not_after_formatted"] = na_dt.strftime("%Y-%m-%d")
                            days_left = (na_dt - now_utc).days
                            cert_info["days_until_expiry"] = days_left
                            cert_info["is_expired"] = (days_left < 0)
                        except Exception:
                            cert_info["not_after"] = na_str

                    cert_info["version"] = cert.get("version")
        except Exception as e:
            log.debug("Live TLS inspection exception for %s: %s", hostname, e)
            cert_info["error"] = str(e)

        return cert_info

    async def _query_certificate_transparency(self, domain: str) -> Dict[str, Any]:
        """
        Queries public Certificate Transparency database (crt.sh).
        """
        ct_result = {
            "ct_available": False,
            "earliest_cert_date": None,
            "total_logged_certificates": 0,
            "earliest_issuer": None,
            "latest_cert_date": None
        }

        try:
            url = f"https://crt.sh/?q={domain}&output=json"
            async with httpx.AsyncClient(timeout=4.0) as client:
                resp = await client.get(url)
                if resp.status_code == 200:
                    records = resp.json()
                    if records and isinstance(records, list):
                        ct_result["ct_available"] = True
                        ct_result["total_logged_certificates"] = len(records)
                        
                        entry_dates = []
                        for r in records:
                            ed = r.get("entry_timestamp") or r.get("not_before")
                            if ed:
                                entry_dates.append(ed.split("T")[0])
                        
                        if entry_dates:
                            sorted_dates = sorted(entry_dates)
                            ct_result["earliest_cert_date"] = sorted_dates[0]
                            ct_result["latest_cert_date"] = sorted_dates[-1]
                            ct_result["earliest_issuer"] = records[0].get("issuer_name", "")[:80]
        except Exception as e:
            log.debug("Certificate transparency query skipped/timed out: %s", e)

        return ct_result

    async def _query_web_archive(self, url: str) -> Dict[str, Any]:
        """
        Queries Wayback Machine availability API for historical snapshots.
        """
        archive_res = {
            "archive_available": False,
            "has_historical_snapshots": False,
            "earliest_snapshot_date": None,
            "snapshot_url": None
        }

        try:
            wb_url = f"https://archive.org/wayback/available?url={url}"
            async with httpx.AsyncClient(timeout=3.5) as client:
                resp = await client.get(wb_url)
                if resp.status_code == 200:
                    data = resp.json()
                    closest = data.get("archived_snapshots", {}).get("closest", {})
                    if closest.get("available"):
                        archive_res["archive_available"] = True
                        archive_res["has_historical_snapshots"] = True
                        archive_res["snapshot_url"] = closest.get("url")
                        timestamp_str = closest.get("timestamp", "")
                        if len(timestamp_str) >= 8:
                            archive_res["earliest_snapshot_date"] = f"{timestamp_str[:4]}-{timestamp_str[4:6]}-{timestamp_str[6:8]}"
        except Exception as e:
            log.debug("Archive query skipped: %s", e)

        return archive_res

certificate_history_engine = CertificateHistoryEngine()
