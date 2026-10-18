# PhishSense Detection Engine Audit & Root Cause Analysis

## Executive Summary
This document provides an exhaustive technical audit of the PhishSense detection pipeline prior to the v4.0 overhaul. It identifies specific architectural, algorithmic, dataset, and inference-time defects that caused unreliability and false predictions on real-world phishing and legitimate URLs.

---

## 1. Dataset & Training Pipeline Defects

### 1.1 Synthetic Behavioral Dataset (`generate_dataset.py`)
- **Defect:** `generate_dataset.py` used hardcoded uniform distributions (e.g., `np.random.randint(0, 25)` for legit anomaly scores and `np.random.randint(30, 60)` for suspicious).
- **Leakage:** The label was directly generated as a function of synthetic features like `frontend_anomaly_score` and `paste_count`.
- **Inference Failure:** In real-world URL scanning, a user pastes a link into the search bar. Real human interaction telemetry on an external, unscanned page does not exist at scan time. Feeding default 0s or synthetic-trained expectations into the behavioral model resulted in severe misclassifications.
- **Remedy:** Decouple URL scanning from behavioral telemetry. Behavioral analysis must only activate during instrumented user sessions, with explicit `INSUFFICIENT_TELEMETRY` flags when absent.

### 1.2 Training vs Inference Feature Semantic Mismatches (`url_extractor.py` vs `5.urldata.csv`)
The Random Forest model (`url_detector.pkl`) was trained on `5.urldata.csv` (16 binary features). However, the runtime extraction in `url_extractor.py` implemented completely different semantic logic:

| Feature Name | Training Semantics (`5.urldata.csv`) | Inference Semantics (`url_extractor.py`) | Severity |
| :--- | :--- | :--- | :--- |
| **`Web_Traffic`** | Alexa Traffic Rank $\le 100,000$ (0=High rank, 1=Low/None) | Shannon entropy $> 4.2$ OR deceptive token substring | **Critical Mismatch** |
| **`Domain_Age`** | WHOIS Domain Age $\ge 6$ months (0=Old, 1=New) | Suffix matching against 21 hardcoded TLDs | **Critical Mismatch** |
| **`Domain_End`** | WHOIS Expiration $> 6$ months | `1 if "." in path else 0` | **Critical Mismatch** |
| **`iFrame`** | Scraped webpage containing hidden iframe | Hardcoded `0` at URL extraction time | **Severe Mismatch** |
| **`Mouse_Over`** | Scraped webpage checking `onmouseover` changes | Hardcoded `0` at URL extraction time | **Severe Mismatch** |
| **`Right_Click`** | Scraped webpage checking right-click disabled | Hardcoded `0` at URL extraction time | **Severe Mismatch** |
| **`Web_Forwards`** | Scraped HTTP redirect count $\ge 4$ | Checking query string for `?url=` or `?redirect=` | **Severe Mismatch** |

**Impact:** The ML model learned weights and splits based on Alexa rank, WHOIS dates, and HTML scraping, but was evaluated at runtime on Shannon entropy, path dots, and zero-filled vectors. This caused erratic predictions on unseen URLs.

### 1.3 Absence of Real Threat Intelligence Lookup
- The previous system had zero integration with active verified phishing databases (PhishTank, OpenPhish, URLhaus).
- Confirmed active phishing campaigns reported across the global cybersecurity community were treated as raw heuristic guesses rather than definitive intelligence matches.

### 1.4 Broken Brand Impersonation & Typosquatting Logic
- Brand detection was limited to exact substring matching of 23 words without identifying:
  - Typosquatting (e.g., `paypa1`, `micros0ft`, `arnazon`).
  - Subdomain deception (e.g., `paypal.com.verify-account.top`).
  - Punycode / IDN homoglyphs (e.g., `xn--...`).

### 1.5 Missing Redirect-Chain Tracing
- Scans did not trace multi-hop HTTP redirections (e.g., shortener $\to$ tracking hop $\to$ final credential harvester).
- Modern phishing campaigns frequently abuse legitimate URL shorteners (bit.ly, t.co) to cloak the final malicious landing domain.

### 1.6 Uncalibrated Probabilities & Binary Oversimplification
- Probabilities from single uncalibrated decision trees were non-monotonic.
- The system suffered from "absence of evidence is evidence of safety" syndrome: if a URL was not in a blacklist and had few heuristic flags, it was prematurely declared 100% Legitimate without accounting for lack of evidence.

---

## 2. Overhaul & Architecture Plan

1. **Dedicated Threat Intelligence Engine (`threat_intel.py`):**
   - Live ingestion and local disk caching of PhishTank, OpenPhish, and URLhaus feeds.
   - Sub-millisecond hash/domain lookup.
   - Separation of **Known Threat Intelligence** from **ML Heuristics**.

2. **Unified Feature Extractor (`feature_extractor.py`):**
   - 100% parity between training pipeline and runtime inference.
   - Robust lexical, structural, statistical (entropy, vowel-consonant ratios, token distribution), and brand impersonation features.
   - Proper extraction of punycode, TLD reputation, and path depth.

3. **Multi-Hop Redirect Tracer & Live DOM Inspector (`redirect_inspector.py`):**
   - Follows redirect hops up to 5 stages, recording full path, status codes, and cross-domain jumps.
   - Evaluates live DOM for password inputs, cross-origin form action destinations, visual hyperlink spoofing, and obfuscated JavaScript.

4. **Calibrated ML Ensemble:**
   - Retrain Random Forest + Gradient Boosting using exact unified features.
   - Ensemble with Calibrated NLP Sub-Token TF-IDF model ($92.9\%$ accuracy on 420k real URLs).
   - Apply `CalibratedClassifierCV` for true posterior probabilities.

5. **Multi-Evidence Decision Engine & Verdict States:**
   - Implement four internal states: `LEGITIMATE`, `SUSPICIOUS`, `PHISHING`, and `INSUFFICIENT_EVIDENCE`.
   - Prevent safe-washing: unverified, unreachable URLs with neutral signals output `INSUFFICIENT_EVIDENCE / UNVERIFIED` rather than clean green legitimate.
   - Standard output schema: `verdict`, `threat_score`, `confidence`, `evidence`, `threat_intel_match`, `redirect_info`, `threat_fingerprint`.
