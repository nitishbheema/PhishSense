"""
domain_intelligence.py — Domain Age, RDAP Registration & DNS Records Intelligence
Module 3:
  - Authoritative RDAP lookup (ICANN/IANA bootstrap)
  - Domain creation date, age calculation, expiry date, registrar
  - Privacy-redacted handling & unsupported TLD handling
  - DNS Records: A, AAAA, NS, MX, TXT (SPF), DMARC (_dmarc.<domain>), DNSSEC
  - Never invents data or assumes new=malicious or old=safe
"""

import logging
import httpx
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional
import dns.resolver
import tldextract

log = logging.getLogger("phishsense-domain-intelligence")

class DomainIntelligenceEngine:
    def __init__(self):
        self.rdap_base = "https://rdap.org/domain"
        self.timeout = 5.0

    def extract_registrable_domain(self, hostname: str) -> str:
        ext = tldextract.extract(hostname)
        if ext.registered_domain:
            return ext.registered_domain.lower()
        return hostname.lower()

    async def get_domain_intelligence(self, domain_or_url: str) -> Dict[str, Any]:
        """
        Retrieves RDAP registration data and DNS record configurations.
        """
        # Clean domain
        clean_target = domain_or_url.strip().lower()
        if "://" in clean_target:
            from urllib.parse import urlparse
            clean_target = urlparse(clean_target).netloc.split(":")[0]
        
        reg_domain = self.extract_registrable_domain(clean_target)
        
        # 1. Fetch RDAP Registration Info
        rdap_data = await self._fetch_rdap(reg_domain)

        # 2. Fetch DNS Records (A, AAAA, MX, NS, TXT, DMARC, DNSSEC)
        dns_data = self._fetch_dns_records(reg_domain)

        # 3. Compute Risk Factor
        age_days = rdap_data.get("domain_age_days")
        status = "NO_ISSUE_DETECTED"
        risk_level = "INFORMATIONAL"
        finding = f"Domain {reg_domain} is registered with active DNS records."

        if age_days is not None:
            if age_days < 14:
                status = "VERY_RECENT_REGISTRATION"
                risk_level = "HIGH"
                finding = f"Domain was registered only {age_days} day(s) ago. Extremely fresh domains have high statistical correlation with disposable attack infrastructure."
            elif age_days < 90:
                status = "RECENT_REGISTRATION"
                risk_level = "MEDIUM"
                finding = f"Domain is relatively new ({age_days} days old, registered {rdap_data.get('creation_date_formatted', '')})."
            else:
                status = "ESTABLISHED_DOMAIN"
                risk_level = "NO_ISSUE_DETECTED"
                finding = f"Established domain ({round(age_days / 365.25, 1)} years old, registered {rdap_data.get('creation_date_formatted', '')}). Note: Established age does not rule out compromised subdomains."
        elif rdap_data.get("unsupported_tld"):
            finding = f"RDAP data is not publicly published for the '{rdap_data.get('tld', '')}' TLD. Domain age could not be established."
        elif rdap_data.get("privacy_redacted"):
            finding = f"Domain registration details are privacy-redacted by registrar ({rdap_data.get('registrar', 'Unknown')})."

        return {
            "domain": reg_domain,
            "status": status,
            "risk_level": risk_level,
            "finding": finding,
            "registration": rdap_data,
            "dns_records": dns_data,
            "source": "ICANN RDAP Bootstrap & Global DNS Resolvers",
            "retrieved_at_utc": datetime.now(timezone.utc).isoformat(),
            "explanation": "Domain age is an independent signal. Fresh registration is one risk indicator; established age does not guarantee website security."
        }

    async def _fetch_rdap(self, reg_domain: str) -> Dict[str, Any]:
        result = {
            "reg_domain": reg_domain,
            "creation_date": None,
            "creation_date_formatted": None,
            "domain_age_days": None,
            "expiry_date": None,
            "last_updated_date": None,
            "registrar": None,
            "status_codes": [],
            "nameservers": [],
            "privacy_redacted": False,
            "unsupported_tld": False,
            "raw_available": False
        }

        try:
            url = f"{self.rdap_base}/{reg_domain}"
            headers = {"Accept": "application/rdap+json, application/json"}
            async with httpx.AsyncClient(timeout=self.timeout, follow_redirects=True) as client:
                resp = await client.get(url, headers=headers)
                if resp.status_code == 200:
                    data = resp.json()
                    result["raw_available"] = True

                    # Extract events: registration, expiration, last changed
                    events = data.get("events", [])
                    now_utc = datetime.now(timezone.utc)
                    for ev in events:
                        action = ev.get("eventAction", "").lower()
                        event_date_str = ev.get("eventDate", "")
                        if event_date_str:
                            try:
                                # Standard ISO 8601 parsing
                                dt = datetime.fromisoformat(event_date_str.replace("Z", "+00:00"))
                                if action in ["registration", "created"]:
                                    result["creation_date"] = dt.isoformat()
                                    result["creation_date_formatted"] = dt.strftime("%Y-%m-%d")
                                    result["domain_age_days"] = max(0, (now_utc - dt).days)
                                elif action in ["expiration", "expires"]:
                                    result["expiry_date"] = dt.strftime("%Y-%m-%d")
                                elif action in ["last changed", "last update"]:
                                    result["last_updated_date"] = dt.strftime("%Y-%m-%d")
                            except Exception as parse_err:
                                log.debug("RDAP date parse issue: %s", parse_err)

                    # Extract entities (Registrar)
                    for ent in data.get("entities", []):
                        roles = ent.get("roles", [])
                        if "registrar" in roles:
                            vcard = ent.get("vcardArray", [])
                            if len(vcard) > 1:
                                for item in vcard[1]:
                                    if len(item) > 3 and item[0] == "fn":
                                        result["registrar"] = str(item[3])
                                        break

                    # Extract Status codes
                    result["status_codes"] = data.get("status", [])

                    # Extract Nameservers
                    ns_list = []
                    for ns in data.get("nameservers", []):
                        ldh = ns.get("ldhName")
                        if ldh:
                            ns_list.append(ldh.lower())
                    result["nameservers"] = ns_list

                    # Privacy Redaction Check
                    text_dump = str(data).lower()
                    if "redacted" in text_dump or "privacy" in text_dump or "whoisguard" in text_dump:
                        result["privacy_redacted"] = True

                elif resp.status_code == 404:
                    result["unsupported_tld"] = True
                    result["notes"] = "Domain RDAP endpoint returned 404 Not Found."
        except Exception as e:
            log.warning("RDAP lookup failed for %s: %s", reg_domain, e)
            result["notes"] = f"RDAP query timed out or unavailable: {str(e)}"

        return result

    def _fetch_dns_records(self, domain: str) -> Dict[str, Any]:
        dns_res = {
            "has_a_records": False,
            "a_records": [],
            "has_aaaa_records": False,
            "aaaa_records": [],
            "mx_records": [],
            "ns_records": [],
            "txt_records": [],
            "spf_record": None,
            "dmarc_record": None,
            "has_dmarc": False,
            "has_spf": False,
            "dnssec_enabled": False,
        }

        resolver = dns.resolver.Resolver()
        resolver.timeout = 2.5
        resolver.lifetime = 2.5

        # 1. A Records
        try:
            answers = resolver.resolve(domain, "A")
            dns_res["a_records"] = [rdata.to_text() for rdata in answers]
            dns_res["has_a_records"] = len(dns_res["a_records"]) > 0
        except Exception:
            pass

        # 2. AAAA Records
        try:
            answers = resolver.resolve(domain, "AAAA")
            dns_res["aaaa_records"] = [rdata.to_text() for rdata in answers]
            dns_res["has_aaaa_records"] = len(dns_res["aaaa_records"]) > 0
        except Exception:
            pass

        # 3. NS Records
        try:
            answers = resolver.resolve(domain, "NS")
            dns_res["ns_records"] = [rdata.to_text().rstrip(".") for rdata in answers]
        except Exception:
            pass

        # 4. MX Records
        try:
            answers = resolver.resolve(domain, "MX")
            dns_res["mx_records"] = [f"{rdata.preference} {rdata.exchange.to_text().rstrip('.')}" for rdata in answers]
        except Exception:
            pass

        # 5. TXT Records & SPF
        try:
            answers = resolver.resolve(domain, "TXT")
            txts = []
            for rdata in answers:
                txt_val = "".join([s.decode("utf-8", errors="replace") if isinstance(s, bytes) else str(s) for s in rdata.strings])
                txts.append(txt_val)
                if txt_val.lower().startswith("v=spf1"):
                    dns_res["spf_record"] = txt_val
                    dns_res["has_spf"] = True
            dns_res["txt_records"] = txts[:10]  # keep first 10
        except Exception:
            pass

        # 6. DMARC Record (_dmarc.<domain>)
        try:
            dmarc_domain = f"_dmarc.{domain}"
            answers = resolver.resolve(dmarc_domain, "TXT")
            for rdata in answers:
                txt_val = "".join([s.decode("utf-8", errors="replace") if isinstance(s, bytes) else str(s) for s in rdata.strings])
                if txt_val.lower().startswith("v=dmarc1"):
                    dns_res["dmarc_record"] = txt_val
                    dns_res["has_dmarc"] = True
                    break
        except Exception:
            pass

        # 7. DNSSEC Check (DNSKEY record)
        try:
            answers = resolver.resolve(domain, "DNSKEY")
            if len(answers) > 0:
                dns_res["dnssec_enabled"] = True
        except Exception:
            dns_res["dnssec_enabled"] = False

        return dns_res

domain_intelligence_engine = DomainIntelligenceEngine()
