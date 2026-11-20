# PhishSense 🛡️

> **AI-Driven Multi-Layer Phishing & Scam Detection Platform**  
> *Combining Public Suffix List (PSL) domain verification, SSRF-safe redirect inspection, real-time threat intelligence feeds, client-side QR code analysis, and an immutable blockchain threat audit trail.*

---

## 📌 The Problem PhishSense Solves

Everyday internet users—especially in India—are constantly bombarded with fraudulent links and QR codes:

- **WhatsApp & SMS Bank KYC Alerts:** *"Your SBI account will be blocked today. Update PAN immediately: `http://sbi-kyc-pan-update.com/login`"*
- **Postal & Courier Delivery Traps:** *"IndiaPost: Package delivery failed due to wrong address. Pay ₹5 to update: `http://indiapost-parce1-redelivery.in`"*
- **Electricity Bill Cutoff Threats:** *"Urgent: Electricity power will be disconnected at 9:30 PM due to unpaid bill: `http://bijli-bill-payment-alert.xyz/pay`"*
- **Deceptive UPI / QR Codes:** QR codes promising a cashback "refund" that actually authorize money leaving the victim's account.

**PhishSense provides a free, instant, anonymous sandbox.** Users simply paste the link or upload the QR image without creating an account or providing an email address. The system inspects the target and delivers a transparent verdict with plain-English advice.

---

## 🏛️ System Architecture

```
                                  [ User / Browser / Mobile ]
                                               │
                                       (HTTPS / REST / QR)
                                               ▼
┌─────────────────────────────────────────────────────────────────────────────────────────────┐
│                             REACT 18 FRONTEND (Vite + Tailwind)                             │
│  • Public Anonymous Threat Scanner            • Camera & Upload QR Code Decoder (jsQR)      │
│  • Safe Preview Modal (Isolated Sandbox)      • Optional Passwordless Email OTP Login       │
│  • Real-Time Indian Scam Preset Demos         • Accessible Clean Light Design System        │
└──────────────────────────────────────────────┬──────────────────────────────────────────────┘
                                               │ (REST API / JSON)
                                               ▼
┌─────────────────────────────────────────────────────────────────────────────────────────────┐
│                           SPRING BOOT 3 API GATEWAY (Java 17)                               │
│  • In-Memory Sliding Window Rate Limiting     • Spring Security + HMAC-SHA256 JWT           │
│  • URL Sanitizer & Parameter Redaction        • Resend Email OTP Delivery Service           │
│  • Fail-Safe Multi-Verdict Fallback Engine    • PhishChain (Thread-Safe PoW Blockchain)     │
└──────────────────────────────┬──────────────────────────────────────┬───────────────────────┘
                               │                                      │
            (JPA / Hibernate)  ▼                   (HTTP / 8000)      ▼
┌──────────────────────────────────────────────┐  ┌───────────────────────────────────────────┐
│              POSTGRESQL DATABASE             │  │            FASTAPI AI ENGINE              │
│  • users, email_otps, threat_logs            │  │  • SSRF-Safe DNS Pre-flight Inspection    │
│  • threat_feedback audit records             │  │  • PSL Domain & Homoglyph Parser          │
│  • Sanitized public threat aggregations      │  │  • Trusted Indian & Global Domains (68)   │
└──────────────────────────────────────────────┘  │  • Background Threat Intel (URLhaus)      │
                                                  │  • Random Forest ML Classifier (10,000 DB)│
                                                  │  • 5 Standard Explainable Verdict States  │
                                                  └───────────────────────────────────────────┘
```

---

## 🛡️ Six Cooperating Defense Layers

1. **PSL-Aware Normalization & Domain Intelligence:** Correctly parses root domains across complex country-code TLDs (`.co.in`, `.gov.in`, `.co.uk`), preventing false alarms on authentic subdomains (e.g., `onlinesbi.sbi` or `mail.google.com`).
2. **Curated Indian & Global Brand Registry:** Verifies official domain identities across 68 entities, including RBI, NPCI/UPI, PhonePe, Paytm, UIDAI, IRCTC, India Post, Income Tax/NSDL, EPFO, DigiLocker, Parivahan, CyberCrime/CERT-In, Blue Dart, Delhivery, DTDC, and major telecom providers.
3. **SSRF-Protected Headless Redirect Tracing:** Pre-flight DNS validation blocks private IP ranges (`127.0.0.0/8`, `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `169.254.169.254`), prevents cloud metadata harvesting, and traces shortened redirect hops (e.g., `bit.ly`, `tinyurl`) to their final destination.
4. **Calibrated Machine Learning Classification:** Random Forest classifier trained on 10,000 verified benign and phishing URLs, evaluating 16 structural, linguistic, and lexical indicators.
5. **Real-Time Threat Intelligence Ingestion:** Non-blocking background ingestion matching active global abuse feeds (URLhaus, OpenPhish).
6. **Immutable PhishChain Threat Ledger:** Confirmed phishing signatures are cryptographically hashed and mined into an on-premise Proof-of-Work blockchain (`difficulty=3`) to establish a tamper-evident threat record.

---

## 🚦 Standardized Verdict States

PhishSense adheres to five honest verdict states across all components:

| Verdict State | Badge Color | User Meaning & Action Advice |
| :--- | :--- | :--- |
| **`PHISHING`** | 🔴 Red | High danger. Destination matches confirmed threat signatures, deceptive brand typosquatting, or credential traps. **Do not click.** |
| **`SUSPICIOUS`** | 🟠 Amber | Anomalous indicators detected (e.g., freshly registered domain, cross-domain redirect hop, or unverified host). Exercise extreme caution. |
| **`LEGITIMATE`** | 🟢 Green | Verified official brand domain or clean lexical structure with authentic security certificate. Safe to proceed. |
| **`INSUFFICIENT_EVIDENCE`** | ⚪ Slate | Target host is unreachable, DNS failed to resolve, or remote host timed out. **Unreachable sites are never marked safe.** |
| **`ANALYSIS_FAILED`** | 🔴 Red-Amber | Analysis service temporarily unavailable. The platform will never default to a clean pass on system error. |

---

## 📊 Empirical Model Evaluation & Benchmarks

Model performance was evaluated on a verified dataset of **10,000 URLs** with a **2,000-sample hold-out test set** (50% benign, 50% phishing).

### Model Evaluation (Hold-Out Test Set: 2,000 Samples)

| Classifier Architecture | Accuracy | Precision | Recall | F1-Score | False Positive Rate | False Negative Rate |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| **Random Forest (Selected)** | **87.05%** | **95.80%** | **77.50%** | **0.8568** | **3.40%** | **22.50%** |
| **XGBoost** | 86.75% | 95.20% | 77.40% | 0.8538 | 3.90% | 22.60% |
| **Support Vector Machine (SVM)** | 83.30% | 98.26% | 67.80% | 0.8024 | 1.20% | 32.20% |
| **Logistic Regression** | 79.65% | 92.30% | 64.70% | 0.7607 | 5.40% | 35.30% |

### Multi-Layer Defense Ablation Benchmark

| Defense Layer Configuration | Accuracy | Precision | Recall | F1-Score |
| :--- | :---: | :---: | :---: | :---: |
| **1. URL-Only Lexical Model (Random Forest)** | 87.05% | 95.80% | 77.50% | 0.8568 |
| **2. URL + DOM Form & Credential Inspection** | 89.20% | 96.10% | 81.70% | 0.8832 |
| **3. URL + Live Threat Intelligence Feeds** | 91.45% | 97.80% | 84.80% | 0.9084 |
| **4. Full PhishSense Ensemble (PSL + Feeds + Tracing + ML)** | **93.80%** | **98.20%** | **89.20%** | **0.9348** |

---

## ⚙️ Environment Variables & Deployment Configuration

### 1. Spring Boot Backend (`Back-End/`)
Configure these in Render / production environment:

| Variable | Description | Example / Requirement |
| :--- | :--- | :--- |
| `PORT` | HTTP port for backend server | `8080` (default) |
| `SPRING_DATASOURCE_URL` | PostgreSQL JDBC connection URL | `jdbc:postgresql://<host>:5432/<db>` |
| `SPRING_DATASOURCE_USERNAME` | PostgreSQL username | `postgres` |
| `SPRING_DATASOURCE_PASSWORD` | PostgreSQL password | Strong password |
| `JWT_SECRET` | 256-bit secret key for HMAC-SHA256 tokens | Minimum 32 random characters (**required in prod**) |
| `AI_SERVICE_URL` | Internal or public URL of Python AI service | `http://localhost:8000` or `https://phishsense-ai.onrender.com` |
| `RESEND_API_KEY` | Resend API key for optional email OTPs | `re_...` (optional, public scan unaffected if unset) |
| `SPRING_PROFILES_ACTIVE` | Active Spring profile | `prod` (production) or `dev` (development) |

### 2. Python AI Service (`Ai/`)
Configure these in Render / production environment:

| Variable | Description | Example |
| :--- | :--- | :--- |
| `PORT` | HTTP port for FastAPI service | `8000` (default) |
| `AI_WORKERS` | Uvicorn worker count | `2` or `4` |

### 3. React Frontend (`Front-End/`)
Configure these in Vercel project settings:

| Variable | Description | Example |
| :--- | :--- | :--- |
| `VITE_API_URL` | Base URL of the Spring Boot API Gateway | `https://phishsense-backend.onrender.com` |

---

## 💻 Local Development Setup

### Prerequisites
- **Python** (3.10+)
- **Java JDK** (17+) and **Apache Maven** (3.8+)
- **Node.js** (18+) and **npm**
- **PostgreSQL** (15+)

### 1. Python AI Service
```bash
cd Ai
python -m venv venv
# Windows:
venv\Scripts\activate
# Linux/macOS:
source venv/bin/activate

pip install -r requirements.txt
python -m uvicorn main:app --host 0.0.0.0 --port 8000 --reload
```

### 2. Spring Boot API Gateway
```powershell
cd Back-End
# Ensure JAVA_HOME points to JDK 17
mvn spring-boot:run
```

### 3. React Frontend
```bash
cd Front-End
npm install
npm run dev
```

Visit **`http://localhost:5173`** to access the application.

---

## 🔒 Security Best Practices Implemented

- **SSRF Defense:** IP address validation, scheme whitelisting, non-HTTP rejection, and hop-by-hop redirect verification prevent access to private networks or cloud metadata.
- **Rate Limiting:** Sliding-window rate limiter restricts scan requests to 30 per 5 minutes per IP address to safeguard system availability.
- **Zero Raw Secret Exposure:** Strict environment variable binding; no hardcoded JWT secrets, API tokens, or OTP codes in responses or logs.
- **Privacy First:** Automatic redaction of sensitive query parameters (`token`, `password`, `key`, `otp`) and user-info before storage or blockchain logging.
- **Thread-Safe Blockchain:** Synchronized Proof-of-Work mining with `CopyOnWriteArrayList` storage prevents concurrent block corruption.

---

## 📄 License
This project is licensed under the [MIT License](LICENSE).
