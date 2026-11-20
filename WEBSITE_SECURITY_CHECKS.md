# PhishSense — Website Security Checks & Technical Standards

**Version:** 4.1.0  
**Date:** November 20, 2026

---

## 1. Overview

This document specifies the exact technical checks, evidence patterns, and evaluation logic implemented in PhishSense for **Content Compromise Inspection**, **HTTP Security Configurations**, and **Website Availability & Technical Health**.

---

## 2. Content & Compromise Inspection (`content_compromise_inspector.py`)

Static HTML and DOM structures are inspected passively for known compromise indicators:

### 2.1 Obfuscated & Packed Scripts
- **Check Logic:** Analyzes inline `<script>` tags and external script sources for known obfuscation signatures.
- **Patterns Evaluated:**
  - Dean Edwards Packer signature: `eval(function(p,a,c,k,e,r)...)`
  - Obfuscated hexadecimal decoding: `eval(unescape(...))` or `eval(decodeURI(...))`
  - Character code injection: High-frequency invocation of `String.fromCharCode` (>10 instances in a single block).
- **Severity:** `HIGH` to `CRITICAL`
- **Why It Matters:** Legitimate websites bundle and minify JavaScript; attackers pack and obfuscate scripts to conceal malicious payload delivery, keyloggers, or credential interceptors.

### 2.2 Hidden Zero-Dimension IFrames
- **Check Logic:** Inspects `<iframe>` tags for hidden CSS attributes or zero dimensions.
- **Patterns Evaluated:**
  - Inline styles containing `display:none`, `visibility:hidden`, `opacity:0`, or `position:absolute; left:-9999px`.
  - HTML attributes `width="0"`, `height="0"`, or `hidden`.
- **Severity:** `HIGH`
- **Why It Matters:** Hidden iframes are standard vectors for drive-by malware downloads, background ad fraud, or covert session hijacking.

### 2.3 Cryptocurrency In-Browser Miners
- **Check Logic:** Cross-references `<script src="...">` domains against known web mining pools.
- **Recognized Signatures:** `coinhive.com`, `coin-hive.com`, `cryptoloot.pro`, `webmine.pro`, `mineralt.io`, `authedmine.com`.
- **Severity:** `CRITICAL`
- **Why It Matters:** In-browser mining steals client CPU resources and indicates unauthorized code injection on the host.

### 2.4 Credential Harvesting & Cross-Origin Form Actions
- **Check Logic:** Dissects `<form>` tags and `<input>` types.
- **Flags:**
  - Form contains sensitive inputs (`type="password"`, `name="cvv"`, `name="pin"`, `name="otp"`, `name="card_number"`, `name="aadhaar"`).
  - Form action targets an unverified external cross-origin domain (e.g. form on `example.com` submits to `collector-endpoint.xyz/drop`).
  - Form submits credentials over unencrypted `http://`.
- **Severity:** `HIGH` to `CRITICAL`

### 2.5 Defacement & Takeover Signatures
- **Check Logic:** Inspects `<title>` and `<h1>` - `<h3>` headers for common defacement group claims.
- **Patterns Evaluated:** `hacked by`, `defaced by`, `pwned by`, `cyber army`, `team defacers`.
- **Severity:** `CRITICAL`

---

## 3. HTTP Security Configuration & Headers (`security_headers_evaluator.py`)

Every HTTP response header is evaluated against OWASP and NIST web security guidelines. Missing headers are reported as **configuration weaknesses**, not automatically classified as malware.

| Header | Optimal Configuration | Status When Missing / Suboptimal | Risk / Impact |
| :--- | :--- | :--- | :--- |
| **Strict-Transport-Security (HSTS)** | `max-age=31536000; includeSubDomains; preload` | `MISSING` or `WARNING` if `max-age < 31536000` | Exposes visitors to SSL-stripping and man-in-the-middle attacks on subsequent visits. |
| **Content-Security-Policy (CSP)** | `default-src 'self'; script-src 'self' ...` (without `'unsafe-inline'` or `'unsafe-eval'`) | `MISSING` or `WARNING` if allows unsafe-inline/eval | The browser cannot restrict external script injection, leaving the site exposed to Cross-Site Scripting (XSS). |
| **X-Content-Type-Options** | `nosniff` | `MISSING` | Browsers may attempt to guess the MIME type of files, enabling script execution from benign file extensions (e.g. `.png`). |
| **X-Frame-Options** | `DENY` or `SAMEORIGIN` (or CSP `frame-ancestors 'self'`) | `MISSING` | Enables Clickjacking attacks where the website is framed inside a transparent overlay to hijack user clicks. |
| **Referrer-Policy** | `strict-origin-when-cross-origin` | `MISSING` (defaults to browser default) | May leak sensitive URL paths and query parameters in HTTP `Referer` headers to third-party endpoints. |
| **Permissions-Policy** | `geolocation=(), camera=(), microphone=()` | `MISSING` | Hardware APIs are not restricted at the HTTP header level. |

### Cookie Security Attributes
- **`Secure` Flag:** Verifies that cookies are only sent over encrypted HTTPS connections.
- **`HttpOnly` Flag:** Prevents client-side scripts from accessing cookies, mitigating cookie-theft XSS.
- **`SameSite` Attribute:** Ensures cookies are restricted in cross-site requests, mitigating Cross-Site Request Forgery (CSRF).

---

## 4. Website Availability & Technical Errors (`website_health_inspector.py`)

Website health inspection is strictly separated from malware detection. A broken image or 404 resource does not mean a website is malicious.

### 4.1 Server Status Code Evaluation
- **HTTP 200 / 301 / 302:** Standard operational responses. Redirect chains are traced to final target.
- **HTTP 400 / 401 / 403 / 404 / 429:** Client errors. Evaluates whether public resources are accessible.
- **HTTP 500 / 502 / 503 / 504:** Server internal failures. Flagged as `SERVER_DOWN_OR_ERROR` with `HIGH` severity.

### 4.2 Latency & Redirect Chain Health
- **Latency Threshold:** Warns if server round-trip latency exceeds 3000 ms.
- **Excessive Redirects:** Flags destinations requiring > 4 redirection hops.
- **Redirect Loops:** Detects if any URL appears more than once in the redirect chain.

### 4.3 Broken Asset Request Sampling
- **Methodology:** Samples up to 6 internal and external asset URLs from `<img>`, `<link rel="stylesheet">`, and `<script src>` tags using lightweight HTTP HEAD requests (timeout: 2.0s per asset).
- **Reporting:** Reports exact broken resource URL, HTTP status code (e.g. 404 Not Found), and recommended fix.
