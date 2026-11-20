# PhishSense — Advanced Website Intelligence Architecture

**Version:** 4.1.0  
**Date:** November 20, 2026  
**Status:** Implemented & Verified

---

## 1. High-Level Architectural Vision

PhishSense has evolved beyond a single-score lexical phishing classifier. Rather than relying solely on superficial features (URL length, character entropy, keyword counts), PhishSense implements an **evidence-based, defense-in-depth architecture**.

When evaluating a web destination, PhishSense interrogates multiple independent technical dimensions:
1. **Phishing & Brand Impersonation Risk** (Public Suffix List parsing, typosquatting edit distance, redirect tracing).
2. **Malware & Threat Intelligence Reputation** (OpenPhish, URLhaus, Google Safe Browsing / Web Risk, VirusTotal passive intelligence).
3. **Website Content & Compromise Signals** (Obfuscated JavaScript, hidden zero-dimension iframes, crypto-miners, defacement tags, cross-origin credential harvesting).
4. **Technology Stack & Lifecycle Detection** (CMS, web server, backend runtime, frontend framework fingerprinting, End-of-Life verification).
5. **Known Vulnerabilities (CVE Intelligence)** (NVD CVE correlation for identified versions with CVSS v3 ratings).
6. **TLS Certificate & Cryptographic Health** (Live SSL handshake, SAN list matching, expiry status, Certificate Transparency earliest issuance dates).
7. **HTTP Security Configuration & Headers** (HSTS, Content-Security-Policy, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, cookie security attributes).
8. **Domain Age & DNS Intelligence** (ICANN RDAP bootstrap, registrar information, SPF, DMARC, DNSSEC).
9. **Website Observation & Change History** (Wayback Machine snapshot dates, Certificate Transparency logs, internal PhishSense first-seen and last-seen timestamps).
10. **Website Availability & Technical Errors** (HTTP response status, round-trip latency, redirect loop detection, broken resource sampling).

Each dimension produces independent findings, technical evidence, confidence ratings, and actionable remediation guidance. **No arbitrary composite number mixes domain age with server uptime and phishing.**

---

## 2. Multi-Service Data Flow

```
                                  [ User / Browser Client ]
                                              │
                      ┌───────────────────────┴───────────────────────┐
                      ▼                                               ▼
         [ Quick Link / QR Check ]                   [ Website Security & Health Audit ]
                      │                                               │
                      │ (POST /api/scan)                              │ (POST /api/audit/website)
                      ▼                                               ▼
┌─────────────────────────────────────────────────────────────────────────────────────────────┐
│                           SPRING BOOT API GATEWAY (Port 8080)                               │
│  • Sliding-Window Rate Limiter (30 requests / 5 mins per IP)                                │
│  • URL Sanitization (Redacts tokens, passwords, query parameters)                           │
│  • Historical Scan Lookup (threat_logs persistence)                                         │
│  • Owner Verification Controller (POST /api/audit/verify-ownership)                         │
└──────────────────────────────────────────────┬──────────────────────────────────────────────┘
                                               │ (HTTP / JSON / Port 8000)
                                               ▼
┌─────────────────────────────────────────────────────────────────────────────────────────────┐
│                           FASTAPI AI & AUDIT ENGINE (Port 8000)                             │
│  • SSRF-Safe Outbound Dispatcher (Pre-flight DNS, loopback & cloud metadata blocking)       │
│  • Parallel Async Inspector Engine (asyncio.gather across 4 concurrent network sub-tasks)   │
│                                                                                             │
│  ┌─────────────────────────┐  ┌─────────────────────────┐  ┌─────────────────────────────┐ │
│  │ threat_reputation.py    │  │ content_compromise.py   │  │ domain_intelligence.py      │ │
│  │ OpenPhish, URLhaus,     │  │ Obfuscated JS, iframes, │  │ RDAP creation, age,         │ │
│  │ Safe Browsing, VT       │  │ miners, defacement      │  │ DNS (A, MX, TXT, DMARC)    │ │
│  └─────────────────────────┘  └─────────────────────────┘  └─────────────────────────────┘ │
│  ┌─────────────────────────┐  ┌─────────────────────────┐  ┌─────────────────────────────┐ │
│  │ certificate_history.py  │  │ tech_stack_detector.py  │  │ cve_intelligence.py         │ │
│  │ Live SSL, SANs, crt.sh, │  │ Server, CMS, JS libs,   │  │ NVD CVE correlation,        │ │
│  │ Wayback Machine archive │  │ EOL lifecycle database  │  │ CVSS v3 ratings             │ │
│  └─────────────────────────┘  └─────────────────────────┘  └─────────────────────────────┘ │
│  ┌─────────────────────────┐  ┌─────────────────────────┐  ┌─────────────────────────────┐ │
│  │ security_headers.py     │  │ website_health.py       │  │ audit_orchestrator.py       │ │
│  │ HSTS, CSP, XFO, XCTO,   │  │ HTTP status, latency,   │  │ Aggregates 10 categories,   │ │
│  │ Cookie security flags   │  │ broken asset sampling   │  │ executive posture summary   │ │
│  └─────────────────────────┘  └─────────────────────────┘  └─────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────────────────────────────────┘
```

---

## 3. Two Distinct Assessment Operational Modes

### Mode A: Public Website Assessment (Default)
- **Scope:** Safe, passive, non-intrusive technical checks.
- **Data Inspected:** Public DNS records, RDAP registry info, HTTP response headers, public static HTML DOM, SSL/TLS handshake, Certificate Transparency logs, public threat feeds.
- **Access:** Completely open, unauthenticated, free for any user to inspect any destination.

### Mode B: Owner-Authorized Security Assessment
- **Scope:** Unlocks deep passive inspection, continuous historical monitoring, and future integration with verified cloud hosting platforms (e.g. Vercel deployment webhooks, Render service monitoring).
- **Verification Mechanism:** Domain ownership verification via DNS TXT record (`phishsense-verification={token}`).
- **Strict Guardrails:** Even in authorized mode, PhishSense **strictly prohibits destructive operations, denial-of-service tests, exploit execution, credential stuffing, or unauthorized port scanning**.

---

## 4. API Endpoints

### Backend (Spring Boot Gateway — `http://localhost:8080`)

| Endpoint | Method | Auth | Description |
| :--- | :---: | :---: | :--- |
| `/api/audit/website` | `POST` | Optional | Initiates a 10-category website audit. Applies IP rate limiting and records audit telemetry. |
| `/api/audit/verify-ownership` | `POST` | Optional | Verifies domain ownership via DNS TXT record matching. |
| `/api/audit/history/{domain}` | `GET` | Optional | Retrieves sanitized historical observations (first seen, scan frequency) for a given domain. |

### AI Microservice (FastAPI — `http://localhost:8000`)

| Endpoint | Method | Description |
| :--- | :---: | :--- |
| `/audit-website` | `POST` | Coordinates parallel execution of all 10 intelligence modules and returns structured findings. |
| `/predict-url` | `POST` | High-speed single URL threat classification (Quick Scan). |
| `/threat-intel/status`| `GET` | Returns threat feed cache update timestamps and active URL/domain rule counts. |

---

## 5. Security & Isolation Controls

1. **SSRF Pre-Flight Validation:** All outbound network connections originate from `redirect_inspector.py` after resolving DNS and verifying that the destination IP does not belong to private networks (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), loopback (`127.0.0.0/8`, `::1`), link-local/cloud metadata (`169.254.169.254`), or multicast ranges.
2. **Zero Remote Code Execution:** Downloaded files are never executed. Static HTML is parsed using BeautifulSoup and regular expressions without evaluating remote JavaScript scripts on the host.
3. **Privacy First:** User URLs are never submitted to public search engines or unencrypted third-party scanning pools without explicit configuration.
