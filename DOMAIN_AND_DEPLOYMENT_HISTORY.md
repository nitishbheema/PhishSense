# PhishSense — Domain Intelligence, Certificate Logs & Deployment History

**Version:** 4.1.0  
**Date:** November 20, 2026

---

## 1. Overview & Conceptual Clarity

A common flaw in rudimentary security tools is conflating different temporal milestones:
- **Domain Registration Date:** The date the domain name was first purchased via a registrar (ICANN RDAP).
- **Earliest SSL Certificate Date:** The earliest cryptographic certificate logged in public Certificate Transparency (CT) logs.
- **Web Archive First Seen Date:** The earliest date public internet crawlers (e.g. Wayback Machine) indexed a snapshot.
- **PhishSense Observation Date:** The date PhishSense first inspected the domain in its local telemetry index.
- **Authoritative Code Deployment Timestamp:** The exact moment source code was compiled and pushed to production hosting (e.g. Vercel, Render, AWS, Netlify).

> [!IMPORTANT]
> **Strict Scientific Standard:** PhishSense **never claims to know an exact code deployment timestamp** for an arbitrary external website without authorized hosting provider API credentials. These milestones are presented in a transparent, independent timeline.

---

## 2. Domain Intelligence & RDAP Architecture (`domain_intelligence.py`)

### 2.1 Registration Data Access Protocol (RDAP)
PhishSense queries official ICANN and IANA RDAP bootstrap servers (`https://rdap.org/domain/{domain}`) to retrieve structured, authenticated registration records without relying on fragile WHOIS text-scraping:

- **Domain Creation Date:** Exact UTC timestamp when the domain was registered.
- **Domain Age Calculation:** Age calculated dynamically in days, months, and years relative to the current UTC timestamp.
- **Registrar Entity:** The ICANN-accredited registrar managing the domain (e.g., GoDaddy, Namecheap, Google Domains / Squarespace, MarkMonitor).
- **Expiration Date:** Projected registration expiration date.
- **Domain Status Codes:** EPP status flags (e.g. `clientTransferProhibited`, `clientDeleteProhibited`, `serverHold`).
- **Privacy-Redaction Awareness:** Detects whether administrative and technical contact records are redacted by GDPR/privacy proxies (e.g. Withheld for Privacy, WhoisGuard).

### 2.2 Domain Age Risk Evaluation
- **Very Recent Registration (< 14 days):** Correlates heavily with disposable attack campaigns. Flagged as `HIGH` severity risk indicator.
- **Recent Registration (14 - 90 days):** Medium advisory indicator.
- **Established Domain (> 90 days):** Clean indicator.  
  *Crucial Rule:* An established domain is **not** assumed to be safe, as aged domains can be hijacked, expire and be re-registered, or host compromised subdomains.

---

## 3. DNS Records & Anti-Spoofing Architecture

PhishSense queries authoritative nameservers via `dnspython` to verify email authentication and routing infrastructure:

| Record Type | Purpose | Security Evaluation |
| :--- | :--- | :--- |
| **A / AAAA** | IPv4 & IPv6 routing addresses | Verifies that the host resolves to accessible public addresses. |
| **NS** | Authoritative Nameservers | Verifies DNS provider identity (e.g. Cloudflare, Route53, Akamai). |
| **MX** | Mail Exchange servers | Identifies mail server endpoints. |
| **TXT (SPF)** | Sender Policy Framework (`v=spf1 ...`) | Verifies which IP addresses are authorized to send email on behalf of the domain. Flagged if missing. |
| **DMARC** | Domain-based Message Authentication (`_dmarc.{domain}`) | Checks for active DMARC policy (`p=reject`, `p=quarantine`, `p=none`). Protects against domain email spoofing. |
| **DNSSEC** | DNS Security Extensions (`DNSKEY` query) | Verifies cryptographic authentication of DNS responses to prevent DNS cache poisoning. |

---

## 4. TLS Certificate Intelligence & Certificate Transparency (`certificate_history.py`)

### 4.1 Live TLS Handshake
PhishSense initiates a direct SSL socket connection to port 443 with SNI:
- **Issuer Identification:** Organization (`O`) and Common Name (`CN`) of the issuing Certificate Authority (e.g., Let's Encrypt, DigiCert, Sectigo, Cloudflare, Amazon).
- **Subject Alternative Names (SANs):** Comprehensive list of all domains covered by the certificate.
- **Hostname Match Check:** Verifies that the inspected hostname matches a SAN entry (or valid wildcard `*.example.com`). Flagged as `HOSTNAME_MISMATCH` if invalid.
- **Validity Window:** Valid From (`NotBefore`) and Expiration (`NotAfter`) timestamps.
- **Days Until Expiry:** Alerts if certificate expires within 14 days or is already expired.

### 4.2 Certificate Transparency (CT) Earliest Issuance Date
PhishSense queries public Certificate Transparency log aggregators (`https://crt.sh/?q={domain}&output=json`) to retrieve:
- Earliest recorded SSL/TLS certificate ever issued for the domain.
- Total number of certificates logged over the domain's lifetime.
- Historical Certificate Authority replacement patterns.

---

## 5. Web Archive & Historical Observations

### 5.1 Public Web Archive History (Wayback Machine)
PhishSense queries the Internet Archive Wayback Machine Availability API (`http://archive.org/wayback/available?url={url}`):
- Indicates whether the destination was historically observed by public web archiving crawlers.
- Returns earliest recorded archive snapshot date and snapshot URL.

### 5.2 PhishSense Internal Observation Records
The Spring Boot backend queries its persistent `threat_logs` database:
- **`first_observed_utc`:** The earliest timestamp this domain was submitted to PhishSense.
- **`last_observed_utc`:** The most recent inspection timestamp.
- **`total_observations`:** Total scan frequency across all PhishSense users.

---

## 6. Authorized Hosting Provider Integrations (Module 9)

For website owners who have verified domain control via DNS TXT verification (`phishsense-verification={token}`):
- **Vercel Deployments:** Webhook & API integration to inspect genuine Git commit hashes, deploy timestamps, and build environment variables.
- **Render Deployments:** Service deploy tracking via Render REST API.
- **Security Guardrail:** Third-party hosting credentials must be entered exclusively in the authenticated user account settings and stored securely on the backend.
