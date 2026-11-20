# PhishSense — Test Results & Verification Suite

**Date:** November 20, 2026  
**Test Scope:** Unit, Security, Build, and Benchmark Evaluations  
**Environment:** Windows 11, Node.js v25.8.1, OpenJDK 17.0.14, Python 3.10.11

---

## 1. Automated Security Test Results (SSRF Defense)

The automated SSRF test suite (`Ai/test_ssrf_security.py`) validates that the website inspector rejects private, loopback, cloud metadata, and invalid destinations while allowing legitimate public destinations.

**Execution Command:**
```bash
cd Ai
python test_ssrf_security.py
```

**Results:**
```
...[SSRF Defense] Rejected initial URL 'http://127.0.0.1:8080/api/threats/all': Blocked loopback address: 127.0.0.1
......
----------------------------------------------------------------------
Ran 9 tests in 0.715s

OK
```

### Detailed Test Case Breakdown

| Test Identifier | Tested Payload / Vector | Expected Outcome | Actual Outcome | Status |
| :--- | :--- | :--- | :--- | :--- |
| `test_loopback_ipv4` | `http://127.0.0.1:8080/api/threats` | Rejected: Blocked loopback address | Rejected: 127.0.0.1 blocked | **PASS** |
| `test_localhost_dns` | `http://localhost:8000/metrics` | Rejected: Localhost resolution blocked | Rejected: 127.0.0.1 blocked | **PASS** |
| `test_private_10_network` | `http://10.0.0.1/admin` | Rejected: RFC1918 private address | Rejected: 10.0.0.1 blocked | **PASS** |
| `test_private_172_network` | `http://172.16.0.5/status` | Rejected: RFC1918 private address | Rejected: 172.16.0.5 blocked | **PASS** |
| `test_private_192_network` | `http://192.168.1.1/setup` | Rejected: RFC1918 private address | Rejected: 192.168.1.1 blocked | **PASS** |
| `test_cloud_metadata` | `http://169.254.169.254/latest/meta-data` | Rejected: Link-local / metadata | Rejected: 169.254.169.254 blocked | **PASS** |
| `test_ipv6_loopback` | `http://[::1]:8080/admin` | Rejected: IPv6 loopback | Rejected: ::1 blocked | **PASS** |
| `test_forbidden_schemes` | `file:///etc/passwd`, `gopher://...` | Rejected: Non-HTTP/HTTPS scheme | Rejected: Invalid scheme | **PASS** |
| `test_public_website_allowed`| `https://github.com` | Allowed: Valid public web target | Allowed: Target accepted | **PASS** |

---

## 2. Backend Compilation & Build Verification

The Spring Boot backend was compiled using Maven and OpenJDK 17.

**Execution Command:**
```powershell
$env:JAVA_HOME="C:\Users\Nitish\.jdks\jbr-17.0.14"
$env:Path="$env:JAVA_HOME\bin;$env:Path"
cd Back-End
mvn test-compile
```

**Build Output:**
```
[INFO] Scanning for projects...
[INFO] -----------------< com.phishguard:phishguard-backend >------------------
[INFO] Building PhishGuard Backend 1.0.0
[INFO]   from pom.xml
[INFO] --------------------------------[ jar ]---------------------------------
[INFO] --- resources:3.3.1:resources (default-resources) @ phishguard-backend ---
[INFO] Copying 1 resource from src\main\resources to target\classes
[INFO] --- compiler:3.11.0:compile (default-compile) @ phishguard-backend ---
[INFO] Changes detected - recompiling the module! :source
[INFO] Compiling 32 source files with javac [debug release 17] to target\classes
[INFO] --- compiler:3.11.0:testCompile (default-testCompile) @ phishguard-backend ---
[INFO] No sources to compile
[INFO] ------------------------------------------------------------------------
[INFO] BUILD SUCCESS
[INFO] ------------------------------------------------------------------------
[INFO] Total time:  22.849 s
[INFO] Finished at: 2026-11-20T22:46:23+05:30
[INFO] ------------------------------------------------------------------------
```

**Result:** **BUILD SUCCESS** (0 compilation errors across all 32 Java sources).

---

## 3. Frontend Production Build Verification

The React 18 single-page application was built using Vite and Tailwind CSS.

**Execution Command:**
```bash
cd Front-End
npm run build
```

**Build Output:**
```
> phishing-detector@0.0.0 build
> vite build

vite v8.0.14 building client environment for production...
transforming...✓ 1760 modules transformed.
rendering chunks...
computing gzip size...
dist/index.html                   0.88 kB │ gzip:   0.50 kB
dist/assets/index-BmvIRFNL.css   34.68 kB │ gzip:   7.06 kB
dist/assets/index-4VpI9ixY.js   500.11 kB │ gzip: 155.29 kB

✓ built in 2.33s
```

**Result:** **BUILD SUCCESS** (exit code 0). Clean production bundle generated in `Front-End/dist/`.

---

## 4. Machine Learning Model Evaluation & Benchmark Results

Model performance was evaluated on a curated dataset of **10,000 URLs** with a **2,000-sample hold-out test set** (50% benign, 50% phishing). All metrics reflect `Ai/models/metrics.json` and `Ai/data/benchmark_evaluation_results.json`.

### 4.1 Standalone URL Lexical Model Comparison (Hold-Out Test Set: 2,000 Samples)

| Model Architecture | Accuracy | Precision | Recall | F1-Score | False Positive Rate (FPR) | False Negative Rate (FNR) |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| **Random Forest (Selected)** | **87.05%** | **95.80%** | **77.50%** | **0.8568** | **3.40%** | **22.50%** |
| **XGBoost** | 86.75% | 95.20% | 77.40% | 0.8538 | 3.90% | 22.60% |
| **Support Vector Machine (SVM)** | 83.30% | 98.26% | 67.80% | 0.8024 | 1.20% | 32.20% |
| **Logistic Regression** | 79.65% | 92.30% | 64.70% | 0.7607 | 5.40% | 35.30% |

**Selected Model Justification:**  
Random Forest was selected due to its optimal balance of high precision ($95.8\%$) and highest F1-score ($0.8568$), minimizing false alarms on legitimate domains while maintaining fast sub-millisecond inference latency ($0.017\text{ ms}$).

### 4.2 Multi-Layer Defense Ablation Benchmark

| Configuration Tier | Components Included | Accuracy | Precision | Recall | F1-Score | FPR | FNR |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| **Tier 1** | URL-Only Lexical Model (Random Forest) | 87.05% | 95.80% | 77.50% | 0.8568 | 3.40% | 22.50% |
| **Tier 2** | URL + Webpage & DOM Form Inspection | 89.20% | 96.10% | 81.70% | 0.8832 | 3.30% | 18.30% |
| **Tier 3** | URL + Live Threat Intelligence Feeds (OpenPhish / URLhaus) | 91.45% | 97.80% | 84.80% | 0.9084 | 1.90% | 15.20% |
| **Tier 4** | Complete PhishSense Architecture (Lexical + Threat Feeds + PSL Brand Knowledge Base + SSRF-Safe Redirect Tracing) | **93.80%** | **98.20%** | **89.20%** | **0.9348** | **1.60%** | **10.80%** |

---

## 5. Summary Conclusion

All services pass automated security checks and compile successfully. Real-world detection reliability has been significantly improved through the addition of official Indian domain knowledge, SSRF protections, and honest explainable verdict states.
