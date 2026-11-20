# PhishSense — Complete Codebase Audit & Fix Plan

**Date:** November 2026  
**Auditors:** Senior Full-Stack, Application Security, AI/ML, and Product Engineering Team  
**Repository:** `https://github.com/nitishbheema/PhishSense.git`  
**Target:** Production Readiness, Security Fixes, and Indian User-Focused Anti-Phishing Defense

---

## 1. Executive Summary

PhishSense is designed to protect everyday users—particularly in India—from fraudulent digital communications received via WhatsApp, SMS, email, and malicious QR codes. Users must be able to verify suspicious links quickly, safely, and without forced registration.

An in-depth architectural and code-level audit of all three system tiers (`Front-End/`, `Back-End/`, and `Ai/`) identified critical security vulnerabilities, detection logic flaws, privacy exposures, and usability barriers. This document records all confirmed issues and lays out the exact remedial engineering plan.

---

## 2. Confirmed Security Vulnerabilities

| ID | Component | Severity | Description |
|---|---|---|---|
| **SEC-01** | `Back-End` / `Ai` | **CRITICAL** | **Silent Fallback to Safe on AI Failure:** When the AI service fails or times out, `ApiControllers.java` and `BehaviorAnalysisService.java` default unknown URLs to `LEGIT` / `LEGITIMATE` with zero risk and artificial confidence, marking active phishing campaigns safe. |
| **SEC-02** | `Ai` (`redirect_inspector.py`) | **CRITICAL** | **Server-Side Request Forgery (SSRF):** `verify=False` disables TLS verification. Outbound HTTP requests follow unvalidated redirects to internal networks, loopback (`127.0.0.1`, `localhost`), link-local/cloud metadata (`169.254.169.254`), and private RFC 1918 IPv4/IPv6 ranges without DNS pre-validation or rebinding protection. |
| **SEC-03** | `Back-End` (`ApiControllers.java`, `SecurityConfig.java`) | **HIGH** | **Privacy Violation & Data Exposure:** Endpoints `/api/threats/all`, `/api/threats/recent`, `/api/scan/history/filter`, and `/api/behavior/recent` are publicly exposed without authentication, leaking user emails, user IDs, and raw URLs (including reset tokens and sensitive query parameters). |
| **SEC-04** | `Back-End` (`JwtService.java`, `application.properties`) | **HIGH** | **Insecure Hardcoded JWT Secret:** Uses a static fallback secret (`phishguard-ultra-secure-jwt-secret-key-32chars-min-2026`) with no production validation or startup failure on weak/missing keys. |
| **SEC-05** | `Back-End` (`AuthService.java`, `application.properties`) | **HIGH** | **Plaintext OTP Leakage & Config Typo:** `application.properties` has `rresend.api-key` (misspelled property name). `AuthService.java` returns `devOtp` in API responses, logs plaintext OTPs to application logs, and stores plaintext OTPs in the database. |
| **SEC-06** | `Back-End` (`RateLimiterService.java`) | **MEDIUM** | **Unprotected Public Scan Endpoints:** Rate limiting only applies to OTP requests and login attempts; public `/api/scan`, `/api/scan/qr`, and `/api/scan/website` endpoints have no IP-based rate limiting, leaving free cloud instances vulnerable to DoS. |

---

## 3. Detection Engine & Algorithmic Limitations

| ID | Component | Severity | Description |
|---|---|---|---|
| **DET-01** | `Front-End` & `Back-End` | **HIGH** | **Scanner Telemetry Contaminating URL Verdicts:** `ScanPage.jsx` passed the user's keystroke/paste telemetry from typing into the search box into the scan request. If `anomalyScore > 40` (e.g. user pasted a link), the UI artificially altered clean URLs (`google.com`, `sbi.co.in`) to `SUSPICIOUS` and added +35 to the risk score. |
| **DET-02** | `Ai` (`main.py`) | **HIGH** | **False Sense of Security on Unknown Websites:** When an unknown site returns HTTP 200 without a password input, `main.py` labeled it `"✓ Live Site Verified ... legitimate page structure"`, suppressed risk score to 18, and fabricated 88% confidence. |
| **DET-03** | `Ai` (`threat_intel.py`) | **MEDIUM** | **Misleading Feed Claims & Blocking Synchronous Refresh:** PhishTank is claimed in documentation but never implemented. In addition, `threat_intel.py` triggers blocking synchronous HTTP requests during user scan requests when cache expires. |
| **DET-04** | `Ai` (`trusted_domains.json`) | **MEDIUM** | **Incomplete Indian Domain Intelligence:** Crucial official portals (RBI, NPCI, PhonePe, Paytm, IRCTC, UIDAI, India Post, Income Tax, EPFO, Parivahan, top Indian couriers) were absent, increasing risk of false flags or missed lookalikes on critical Indian services. |

---

## 4. Frontend API & User Experience Problems

| ID | Component | Severity | Description |
|---|---|---|---|
| **UI-01** | `Front-End` (`api.js`) | **HIGH** | **Truthy Error Object Bug:** `post()` returns `{ error: '...' }` on network failure. `scanUrl()` checked `if (result) return result;`, treating the error object as a successful scan response, preventing fallback and breaking UI error handling. |
| **UI-02** | `Front-End` (`ScanPage.jsx`) | **MEDIUM** | **Missing Standard Verdict States:** Lacks explicit handling for `INSUFFICIENT_EVIDENCE` and `ANALYSIS_FAILED`. Users were never honestly told when evidence was inconclusive or servers were unreachable. |
| **UI-03** | `Front-End` (`LandingPage.jsx`) | **MEDIUM** | **Complex & Alienating Jargon:** Homepage previously displayed mock SOC telemetry rather than addressing everyday human concerns (WhatsApp fraud, fake bank KYC SMS, electricity bill threats, QR lottery scams). |

---

## 5. Blockchain & Ledger Limitations

| ID | Component | Severity | Description |
|---|---|---|---|
| **BC-01** | `Back-End` (`PhishChain.java`) | **MEDIUM** | **Non-Thread-Safe In-Memory Ledger:** `ArrayList` used for blockchain blocks and mempool without synchronization; concurrent requests cause race conditions and ledger corruption. |
| **BC-02** | `Back-End` (`PhishChain.java`) | **MEDIUM** | **Unsanitized Transaction Payload:** Full unredacted URLs with private query parameters were included in block transactions and exposed publicly on the blockchain ledger endpoint. |

---

## 6. Model Evaluation & Research Discrepancies

| ID | Component | Description | Action Required |
|---|---|---|---|
| **RES-01** | `benchmark_evaluation_results.json` | Fabricated 100% metrics across all configurations on a mock 200-sample set. | Replace with reproducible, honest evaluation benchmarks and clearly distinguish preliminary URL-only model benchmarks from multi-modal fusion. |
| **RES-02** | `metrics.json` vs `README.md` | `metrics.json` shows real Random Forest test F1 of 85.68% (87.05% accuracy) on 10k dataset, while README claimed 97.4% and 100%. | Reconcile README and UI with documented, reproducible metrics. |

---

## 7. Implementation Roadmap & Status

- [ ] **Phase 2.1:** Implement safe 5-state verdict model (`PHISHING`, `SUSPICIOUS`, `LEGITIMATE`, `INSUFFICIENT_EVIDENCE`, `ANALYSIS_FAILED`) in Back-End and AI service; guarantee AI unavailability never produces `LEGITIMATE`.
- [ ] **Phase 2.2:** Comprehensive SSRF protection in `redirect_inspector.py` (scheme checks, private/loopback/cloud IP blocking, DNS pre-resolution, redirect hop validation, verify TLS certificates). Add SSRF security test suite.
- [ ] **Phase 2.3:** Privacy hardening in Back-End (restrict sensitive retrieval endpoints, URL query parameter/credential redaction, sanitize aggregate dashboard metrics).
- [ ] **Phase 2.4:** Secure JWT configuration (remove hardcoded secrets, enforce `JWT_SECRET` in production, validate key strength).
- [ ] **Phase 2.5:** Fix Resend API key property name (`resend.api-key`), remove `devOtp`, eliminate raw OTP logging, keep optional authentication functional.
- [ ] **Phase 3.1:** Decouple scanner-page behavioral tracking from target URL risk scoring.
- [ ] **Phase 3.2:** Multi-evidence risk fusion and honest explainability without artificial inflation.
- [ ] **Phase 3.3:** Expand trusted Indian domain coverage (Banking, UPI, Gov, Courier, E-Commerce, Identity).
- [ ] **Phase 3.4:** Streamline threat intelligence (OpenPhish, URLhaus, remove PhishTank claims, background non-blocking refresh).
- [ ] **Phase 4:** User-centric UI overhaul: Indian fraud scenarios, plain-language explanations, 3 clear scan options (URL, QR, Website).
- [ ] **Phase 6:** Fix frontend API utility error handling and truthy error object bug.
- [ ] **Phase 7:** Per-IP rate limiting on public scan endpoints.
- [ ] **Phase 8:** Blockchain ledger thread-safety and sensitive data redaction.
- [ ] **Phase 9:** Reconcile benchmark evaluation documents and README.
- [ ] **Phase 10:** Automated test suite execution across Frontend, Backend, and AI service.
