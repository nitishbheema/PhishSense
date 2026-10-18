# PhishSense 🛡️

> **AI-Based Phishing Detection with Blockchain-Backed Threat Intelligence**  
> *An end-to-end defense-in-depth platform combining Public Suffix List (PSL) domain verification, calibrated machine learning ensembles, real-time threat feeds, client-side QR decoding, and an on-premise Proof-of-Work blockchain audit trail.*

---

## 📌 Overview

Phishing attacks have evolved far beyond basic spoofed emails and obvious lookalike domains. Modern adversaries employ **Unicode Punycode homoglyphs**, **brand-impersonating subdomains** (e.g., `google.com.attacker.com`), **multi-hop redirection cloaking**, and **malicious QR codes (quishing)** that evade conventional blacklists and single-model lexical classifiers.

**PhishSense** solves this by fusing **six independent, cooperating defense layers**:
1. **PSL-Aware URL Normalization Engine**: Correctly isolates root domains across complex country-code TLDs (`.co.in`, `.co.uk`) and brand gTLDs (`.microsoft`), eliminating false positives on legitimate subdomains (e.g., `mail.google.com/mail/u/0/#inbox`).
2. **Trusted Domain Knowledge Base (v2.0)**: Curated database of 229 verified domains across 53 brand clusters with 9-level hierarchical matching (subdomain authorization, typosquatting edit distance, and multi-tenant hosting protection).
3. **Real-Time Threat Intelligence**: Sub-millisecond cached lookups against live community feeds (OpenPhish, URLhaus).
4. **Dynamic Redirect & DOM Inspector**: Traces HTTP hops up to 5 tiers and inspects landing pages for deceptive hyperlinks and external credential-harvesting form actions.
5. **Calibrated Machine Learning Ensemble**: Soft-voting classifier (Random Forest + XGBoost) combined with a 150,000-URL TF-IDF sub-token classifier, calibrated via `CalibratedClassifierCV` (sigmoid).
6. **PhishChain Blockchain Ledger**: SHA-256 Proof-of-Work blockchain with Merkle trees ensuring immutable, tamper-evident audit logging for all threat detections.

---

## 🏛️ System Architecture

```
                                  [ User / Browser / Mobile ]
                                               │
                                       (HTTPS / REST / QR)
                                               ▼
┌─────────────────────────────────────────────────────────────────────────────────────────────┐
│                             REACT 18 FRONTEND (Vite + Tailwind)                             │
│  • Interactive Dashboard & Threat Scanner     • Camera-Driven QR Code Decoder (jsQR)       │
│  • Real-Time Behavioral Telemetry HUD         • Passwordless Email OTP & Device Management  │
└──────────────────────────────────────────────┬──────────────────────────────────────────────┘
                                               │ (Bearer JWT / 8080)
                                               ▼
┌─────────────────────────────────────────────────────────────────────────────────────────────┐
│                           SPRING BOOT 3 API GATEWAY (Java 17)                               │
│  • Spring Security + HMAC-SHA256 JWT          • In-Memory Sliding Window Rate Limiting      │
│  • Multi-Modal Request Orchestration          • Security Alert Service                      │
│  • PhishChain (SHA-256 Proof-of-Work Mining)  • JavaMail SMTP Delivery                      │
└──────────────────────────────┬──────────────────────────────────────┬───────────────────────┘
                               │                                      │
            (JPA / Hibernate)  ▼                   (HTTP / 8000)      ▼
┌──────────────────────────────────────────────┐  ┌───────────────────────────────────────────┐
│              POSTGRESQL DATABASE             │  │            FASTAPI AI ENGINE              │
│  • users, email_otps, threat_logs            │  │  • RFC 3986 Normalization & PSL Parser    │
│  • behavior_sessions, security_alerts        │  │  • Trusted Domain Manager (229 domains)   │
│  • threat_feedback audit records             │  │  • Threat Intelligence Feeds Ingestion    │
└──────────────────────────────────────────────┘  │  • Redirect & DOM Form Inspector          │
                                                  │  • 47-Feature Vector Extractor            │
                                                  │  • Calibrated Ensemble (RF + XGB + TF-IDF)│
                                                  │  • Multi-Evidence Risk Fusion Engine      │
                                                  └───────────────────────────────────────────┘
```

---

## 🚀 Key Features

- **Multi-Modal Threat Ingestion**: Accepts URLs via direct keyboard input, camera-based QR code scanning, image file upload, and rendered webpage DOM fetching.
- **Pre-Navigation Quishing Protection**: Decodes QR matrices client-side and performs comprehensive threat analysis before any navigation takes place.
- **Zero-False-Positive Root Verification**: Isolates `#` fragments and benign routes (`/mail/u/0/`, `/login`) on authenticated services.
- **Tamper-Evident Threat Audit Trail**: Every high-risk scan is bundled into a cryptographic block with Merkle tree verification and mined on-premise (`difficulty=3`).
- **Explainable AI (XAI)**: Generates clear, human-readable reasons explaining *why* a domain is safe, suspicious, or malicious.
- **Secure Authentication**: Passwordless login using cryptographically random 6-digit OTPs sent via SMTP, with brute-force lockout and session revocation.

---

## 📊 Empirical Evaluation & Benchmark Results

Evaluated on an empirical benchmark of **162 real-world URLs** (107 legitimate domains spanning 15 global sectors and 55 active phishing, lookalike, and homoglyph attacks):

| Metric | Measured Score | Evaluation Target | Status |
| :--- | :---: | :---: | :---: |
| **Precision** | **100.0%** | $\ge 95.0\%$ | Optimal |
| **Recall / Detection Rate** | **100.0%** | $\ge 95.0\%$ | Optimal |
| **F$_1$-Score** | **1.0000** | $\ge 0.950$ | Optimal |
| **False Positive Rate (FPR)** | **0.00%** | $< 1.0\%$ | 0 False Alarms |
| **False Negative Rate (FNR)** | **0.00%** | $< 1.0\%$ | 0 Missed Attacks |
| **Brier Probability Calibration** | **0.0207** | $< 0.05$ | Well-Calibrated |
| **Trusted Domain Coverage** | **98.13%** | $> 90.0\%$ | Comprehensive |
| **Mean Detection Latency** | **922 ms** | $< 2500\text{ ms}$ | High Performance |

---

## 📂 Repository Structure

```
PhishSense/
├── Ai/                                  # Python FastAPI AI & Threat Intelligence Microservice
│   ├── data/
│   │   ├── trusted_domains.json         # PSL-aware Knowledge Base (53 brands, 229 domains)
│   │   └── threat_intel_cache.json      # Cached OpenPhish & URLhaus feeds
│   ├── models/                          # Trained & Calibrated Machine Learning Pipelines
│   │   ├── calibrated_url_ensemble.pkl  # Calibrated Random Forest + Gradient Boosting
│   │   ├── tfidf_url_model.pkl          # Sub-token TF-IDF Logistic Regression
│   │   └── phish_detector.pkl           # Behavioral Telemetry Interaction Model
│   ├── feature_extractor.py             # 47-D Lexical & Structural Feature Extractor
│   ├── trusted_domain_manager.py        # PSL Root Extractor & Homoglyph Engine
│   ├── redirect_inspector.py            # Headless HTTP Redirect & DOM Inspector
│   ├── threat_intel.py                  # Live Feed Ingestion & Caching Engine
│   ├── main.py                          # FastAPI Application & Orchestration
│   └── requirements.txt                 # Python Dependencies
│
├── Back-End/                            # Spring Boot 3 API Gateway & Blockchain Node
│   ├── src/main/java/com/phishguard/
│   │   ├── blockchain/
│   │   │   └── PhishChain.java          # SHA-256 Proof-of-Work Blockchain & Merkle Trees
│   │   ├── config/                      # Security, CORS & JWT Filters
│   │   ├── controller/                  # REST Controllers (/scan, /auth, /blockchain, etc.)
│   │   ├── model/                       # JPA Entities (PostgreSQL)
│   │   └── service/                     # Business Logic, Email OTP & Threat Analysis
│   ├── pom.xml                          # Maven Project Configuration
│   └── run_backend.bat                  # Local Execution Script
│
├── Front-End/                           # React 18 Single-Page Application (Vite + Tailwind)
│   ├── src/
│   │   ├── components/                  # Navbar, Modals, Behavioral HUD, QR Scanner
│   │   ├── pages/                       # Dashboard, ScanPage, LoginGate, Demo Pages
│   │   └── services/api.js              # REST Client for Backend API Gateway
│   ├── package.json                     # Frontend Dependencies
│   └── vite.config.js                   # Vite Bundler Configuration
│
├── PhishSense_IEEE_Paper.tex            # Full IEEE Conference Research Paper (LaTeX)
├── START_ALL.bat                        # Automated 1-Click Startup Script for All Services
└── .gitignore                           # Git Exclusion Rules
```

---

## 🛠️ Getting Started & Installation

### Prerequisites
- **Git** ($\ge 2.40$)
- **Python** ($3.10+$)
- **Java JDK** ($17+$) & **Apache Maven** ($3.8+$)
- **Node.js** ($18+$) & **npm**
- **PostgreSQL** ($15+$) running on `localhost:5432` with database `phishguard`

---

### Step 1: Clone Repository
```bash
git clone https://github.com/nitishbheema/PhishSense.git
cd PhishSense
```

### Step 2: Setup Python AI Service
```bash
cd Ai
python -m venv venv
# On Windows:
venv\Scripts\activate
# On Linux/macOS:
source venv/bin/activate

pip install -r requirements.txt
python -m uvicorn main:app --host 0.0.0.0 --port 8000
```

### Step 3: Setup Spring Boot API Gateway
```bash
cd ../Back-End
# Configure PostgreSQL and SMTP in src/main/resources/application.properties or environment variables
mvn spring-boot:run
```

### Step 4: Setup React Frontend
```bash
cd ../Front-End
npm install
npm run dev
```

The frontend will be available at **`http://localhost:5173`**.

---

## ⚡ 1-Click Startup (Windows)
You can launch all three microservices concurrently using the root startup script:
```cmd
START_ALL.bat
```

---

## 📜 Research Paper Citation

If you use or reference PhishSense in your academic research, please cite our IEEE paper:

```bibtex
@inproceedings{teja2026phishsense,
  title     = {PhishSense: AI-Based Phishing Detection with Blockchain-Backed Threat Intelligence},
  author    = {M. Dharma Teja and Bheema Nitish Guru Datha and Gajjala Charitha},
  booktitle = {Proceedings of the IEEE International Conference on Cyber Security and Automated Threat Detection},
  year      = {2026}
}
```

---

## 📄 License
This project is licensed under the [MIT License](LICENSE).
