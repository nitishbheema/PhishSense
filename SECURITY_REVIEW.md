# PhishSense — Security Review & Vulnerability Remediation

**Date:** November 20, 2026  
**Auditor:** Application Security & DevSecOps Review  
**Project:** PhishSense  
**Status:** Remediated & Hardened

---

## 1. Threat Model & Scope

PhishSense accepts arbitrary user input (URLs, image files, QR codes) from anonymous public internet clients and interacts with external network destinations to analyze web structures and redirect chains. The attack surface encompasses:

1. **Outbound Network Probing (SSRF):** Attacker crafts URLs targeting internal services, container networks, cloud metadata endpoints (`169.254.169.254`), or loopback addresses.
2. **Denial of Service (DoS):** Attacker floods scan endpoints with high-frequency automated requests.
3. **Data Exposure & Privacy Leaks:** Public endpoints returning scanned target parameters, authorization tokens, or user scan logs.
4. **Authentication & Cryptographic Flaws:** Weak JWT secrets, hardcoded API keys, and insecure OTP handling.
5. **State Manipulation & Race Conditions:** Concurrent writes to the blockchain ledger.

---

## 2. Vulnerability Assessment & Remediation Matrix

### 2.1 Server-Side Request Forgery (SSRF) — Critical

- **Previous State:** `Ai/redirect_inspector.py` received user-submitted URLs and followed redirects using `requests` with `verify=False` and automatic redirect following. No destination IP address checks were performed prior to making outbound HTTP connections.
- **Risk:** Malicious users could submit `http://169.254.169.254/latest/meta-data/` to harvest cloud credentials (AWS/GCP/Render metadata), or probe internal cluster services (`http://localhost:8080`, `http://10.0.0.5:5432`).
- **Remediation Implemented:**
  1. **Pre-flight DNS Resolution & IP Filtering:** Before connecting to any hostname, `redirect_inspector.py` resolves DNS records via `socket.getaddrinfo()`. Every resolved IP is checked against forbidden ranges:
     - Loopback (`127.0.0.0/8`, `::1`)
     - Private networks (RFC 1918: `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`)
     - Link-local and cloud metadata (`169.254.0.0/16`, `fe80::/10`)
     - Multicast (`224.0.0.0/4`, `ff00::/8`)
     - Unspecified / broadcast (`0.0.0.0/8`, `255.255.255.255`)
  2. **Scheme Whitelisting:** Strictly accepts `http` and `https`. Rejects `file://`, `gopher://`, `ftp://`, `ldap://`, etc.
  3. **Embedded Credential Rejection:** Rejects URLs containing `user:pass@host` to prevent authentication spoofing and parser confusion.
  4. **Manual Redirect Traversal:** Disabled automatic redirect following (`follow_redirects=False` in `httpx`). Every hop is extracted, independently validated through the SSRF check, and only followed if safe.
  5. **TLS Enforcement:** Enabled certificate validation (`verify=True`).
- **Verification:** 9 automated test cases in `Ai/test_ssrf_security.py` confirmed 100% rejection of loopback, RFC1918, IPv6, cloud metadata, and forbidden schemes.

---

### 2.2 Insecure Fallback & Fail-Safe Defaults — High

- **Previous State:** If the Python AI service was unavailable, the backend controller caught the `ResourceAccessException` and defaulted `aiResult` to an empty payload. In `BehaviorAnalysisService.java`, missing AI scores defaulted to zero risk, returning verdict `LEGIT`.
- **Risk:** An attacker could execute DoS against the AI service or submit scans during backend network latency, tricking the platform into certifying active phishing campaigns as clean.
- **Remediation Implemented:**
  1. When AI service communication fails, the backend evaluates lexical emergency heuristics.
  2. If clear phishing markers exist, it outputs `PHISHING` or `SUSPICIOUS`.
  3. In all other cases, it strictly assigns `INSUFFICIENT_EVIDENCE` or `ANALYSIS_FAILED`.
  4. **Rule:** An offline or unreachable component can *never* produce a `LEGITIMATE` verdict.

---

### 2.3 JWT Secret Security & Cryptographic Strength — High

- **Previous State:** `JwtService.java` fell back to a hardcoded 32-character plaintext string (`mySecretKey12345678901234567890123456789012`) if `JWT_SECRET` was omitted from the environment.
- **Risk:** Known default secrets allow attackers to forge admin or user JWT tokens, bypassing authentication entirely.
- **Remediation Implemented:**
  1. Added `@PostConstruct` validation in `JwtService.java`.
  2. In production (`prod` / `production` profile), `JWT_SECRET` must be set and must meet the minimum 256-bit (32 bytes) length requirement. Startup halts with `IllegalStateException` if missing or using default values.
  3. In local development, if unset, an ephemeral cryptographically secure 256-bit key is generated via `SecureRandom` on startup.

---

### 2.4 Privacy & Sensitive Parameter Redaction — Medium

- **Previous State:** URLs submitted for analysis could contain active authentication tokens (`https://example.com/reset?token=xyz123`, `otp=987654`, `session=...`). Storing raw URLs in the database or hashing them into the blockchain leaked sensitive parameters.
- **Risk:** Session hijacking or credential theft through threat feed sharing.
- **Remediation Implemented:**
  1. Created `UrlSanitizer.java` utility in `com.phishguard.util`.
  2. Strips URL user-info (`user:pass@`).
  3. Strips URL fragments (`#auth_token=...`).
  4. Redacts sensitive query parameters: `token`, `password`, `key`, `otp`, `session`, `email`, `auth`, `api_key`, `secret`, `access_token`, replacing values with `[REDACTED]`.
  5. URL sanitization executes before database persistence and before blockchain block generation.

---

### 2.5 Denial of Service & Rate Limiting — Medium

- **Previous State:** Scan endpoints (`/api/scan/url`, `/api/scan/qr`, `/api/website/analyze`) were unauthenticated and lacked request throttling.
- **Risk:** Scripted bots could exhaust thread pools, flood database connections, or trigger thousands of outbound HTTP requests.
- **Remediation Implemented:**
  1. Implemented sliding-window rate limiting in `RateLimiterService.java`.
  2. Tracks requests by remote client IP (`allowScanRequest(ip)`).
  3. Enforces a limit of 30 scans per 5-minute rolling window per IP.
  4. Returns HTTP 429 (`Too Many Requests`) with an informative error message and `Retry-After: 300` header.

---

### 2.6 Endpoint Exposure & Principle of Least Privilege — Medium

- **Previous State:** The backend exposed `/api/threats/all`, which returned the entire contents of the `threat_logs` database table to any unauthenticated caller.
- **Remediation Implemented:**
  1. Removed the `/api/threats/all` endpoint.
  2. Public aggregation endpoints (`/api/threats/recent`, `/api/threats/families`) now sanitize outputs, omitting user IDs, user emails, and tokenized query strings.
  3. User scan history endpoints (`/api/scan/history`) require authenticated JWT Bearer authentication.

---

### 2.7 OTP & Email Service Security — Low

- **Previous State:** In `AuthService.java`, OTP generation returned `rawOtpForDev` in JSON API responses, and the configuration contained a misspelled key `rresend.api-key`.
- **Remediation Implemented:**
  1. Fixed configuration property to `resend.api-key` bound to `RESEND_API_KEY`.
  2. Removed `devOtp` / `rawOtpForDev` from API responses.
  3. Removed raw OTP logging to console; masked email addresses in operational logs (`j***@example.com`).

---

## 3. Continuous Security Recommendations

1. **Deployment Secrets Management:** Ensure `JWT_SECRET`, `RESEND_API_KEY`, and `SPRING_DATASOURCE_PASSWORD` are injected exclusively through Render and Vercel environment dashboards.
2. **Reverse Proxy IP Trust:** When running behind a reverse proxy (e.g. Render, Cloudflare), configure `server.forward-headers-strategy=native` in Spring Boot so `getRemoteAddr()` inspects trusted `X-Forwarded-For` headers safely.
3. **Database Retention Automation:** Implement a scheduled cleanup job (e.g., Spring `@Scheduled(cron = "0 0 2 * * ?")`) to prune guest scan records older than 90 days.
