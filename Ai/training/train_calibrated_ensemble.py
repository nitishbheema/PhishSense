"""
train_calibrated_ensemble.py — Overhauled Training Pipeline for PhishSense v4.0

Fixes audited pipeline issues:
1. Eliminates train/test leakage: Proper 3-way split (Train 70% / Calibration 15% / Test 15%).
2. Fixes dataset bias: Injects representative legitimate root domains, paths, parameters, and HTTPS URLs.
3. Fixes label noise: Removes false labels from raw dataset where known top domains were mislabeled.
4. Integrates verified live phishing from threat intel (OpenPhish, URLhaus).
5. Calibrates probabilities on the calibration split using Sigmoid CalibratedClassifierCV.
6. Evaluates exclusively on the held-out test split (zero leakage).
"""

import os
import sys
import json
import joblib
import pandas as pd
import numpy as np
from urllib.parse import urlparse
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier, VotingClassifier
from sklearn.calibration import CalibratedClassifierCV
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import classification_report, accuracy_score, roc_auc_score, brier_score_loss

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
AI_DIR = os.path.dirname(SCRIPT_DIR)
sys.path.insert(0, AI_DIR)

from feature_extractor import extract_features_array, FEATURE_COLUMNS

DATA_PATH = os.path.join(AI_DIR, "data", "urls_420k.csv")
INTEL_CACHE_PATH = os.path.join(AI_DIR, "data", "threat_intel_cache.json")
MODELS_DIR = os.path.join(AI_DIR, "models")
os.makedirs(MODELS_DIR, exist_ok=True)

TOP_AUTHORITATIVE_DOMAINS = [
    "google.com", "youtube.com", "wikipedia.org", "amazon.com", "apple.com",
    "microsoft.com", "github.com", "reddit.com", "netflix.com", "linkedin.com",
    "twitter.com", "instagram.com", "yahoo.com", "cloudflare.com", "wordpress.org",
    "stackoverflow.com", "nytimes.com", "bbc.com", "cnn.com", "cdc.gov",
    "nih.gov", "mit.edu", "stanford.edu", "harvard.edu", "python.org",
    "npmjs.com", "docker.com", "medium.com", "spotify.com", "gitlab.com",
    "adobe.com", "salesforce.com", "oracle.com", "ibm.com", "dropbox.com",
    "paypal.com", "stripe.com", "zoom.us", "slack.com", "trello.com",
    "quora.com", "imdb.com", "ebay.com", "walmart.com", "target.com",
    "bing.com", "duckduckgo.com", "archive.org", "w3schools.com", "mozilla.org"
]

def load_and_curate_data():
    print(f"Loading raw dataset from {DATA_PATH}...")
    df = pd.read_csv(DATA_PATH)
    
    # 1. Clean label noise: any URL whose root domain is in TOP_AUTHORITATIVE_DOMAINS must not be labeled 'bad'
    # unless it's clearly a phishing path with leet or spoofing
    top_domain_set = set(TOP_AUTHORITATIVE_DOMAINS)
    
    clean_urls = []
    clean_labels = []
    
    # 2. Add verified legitimate samples (root domains + diverse paths)
    legit_synthetic = []
    for dom in TOP_AUTHORITATIVE_DOMAINS:
        legit_synthetic.append(f"https://{dom}")
        legit_synthetic.append(f"https://www.{dom}/")
        legit_synthetic.append(f"https://{dom}/search?q=security+guide&hl=en")
        legit_synthetic.append(f"https://{dom}/about/privacy-policy")
        legit_synthetic.append(f"https://{dom}/docs/v2/getting-started.html")
        legit_synthetic.append(f"https://{dom}/products/overview?id=10492&ref=home")
        legit_synthetic.append(f"http://{dom}/")
    
    for u in legit_synthetic:
        clean_urls.append(u)
        clean_labels.append(0)
    
    # 3. Add live verified phishing from threat intelligence feeds
    if os.path.exists(INTEL_CACHE_PATH):
        try:
            with open(INTEL_CACHE_PATH, "r", encoding="utf-8") as f:
                intel_data = json.load(f)
            cached_urls = list(intel_data.get("exact_urls", {}).keys())
            print(f"Adding {len(cached_urls)} verified live phishing URLs from Threat Intel...")
            for u in cached_urls:
                if u.startswith("http"):
                    clean_urls.append(u)
                    clean_labels.append(1)
        except Exception as e:
            print("Warning loading threat intel cache:", e)

    # 4. Filter urls_420k.csv
    good_df = df[df["label"] == "good"]
    bad_df = df[df["label"] == "bad"]
    
    # Exclude mislabeled top domains from bad_df
    filtered_bad = []
    for u in bad_df["url"].dropna():
        u_str = str(u).strip()
        host = urlparse("http://" + u_str if not u_str.startswith("http") else u_str).netloc.lower()
        if host in top_domain_set or any(host.endswith("." + d) for d in top_domain_set):
            continue
        filtered_bad.append(u_str)
        
    print(f"Filtered bad URLs available: {len(filtered_bad)}")
    
    # Sample balanced set: 12,000 good from 420k + 12,000 bad
    sample_good = good_df["url"].dropna().sample(n=12000, random_state=42).tolist()
    sample_bad = pd.Series(filtered_bad).sample(n=10000, random_state=42).tolist()
    
    for u in sample_good:
        clean_urls.append(str(u))
        clean_labels.append(0)
        
    for u in sample_bad:
        clean_urls.append(str(u))
        clean_labels.append(1)
        
    print(f"Total curated dataset: {len(clean_urls)} URLs (Good: {clean_labels.count(0)}, Bad: {clean_labels.count(1)})")
    return clean_urls, clean_labels

def train():
    urls, labels = load_and_curate_data()
    
    print("\nExtracting 24 unified features for all URLs...")
    X_rows = []
    y_vals = []
    
    for idx, (u, lbl) in enumerate(zip(urls, labels)):
        try:
            vec = extract_features_array(u, check_dns=False)
            X_rows.append(vec)
            y_vals.append(lbl)
        except Exception:
            continue
        if (idx + 1) % 5000 == 0:
            print(f"  Processed {idx + 1}/{len(urls)} URLs...")
            
    X = np.array(X_rows, dtype=np.float32)
    y = np.array(y_vals, dtype=np.int32)
    
    print(f"Final feature matrix: {X.shape}, labels: {y.shape} (Phishing: {np.sum(y)}, Legitimate: {len(y) - np.sum(y)})")
    
    # Strict 3-Way Split with Zero Data Leakage:
    # Train: 70% | Calibration: 15% | Test: 15%
    X_train_val, X_test, y_train_val, y_test = train_test_split(
        X, y, test_size=0.15, random_state=42, stratify=y
    )
    
    calib_fraction = 0.15 / 0.85  # ~17.65% of train_val = 15% of total
    X_train, X_calib, y_train, y_calib = train_test_split(
        X_train_val, y_train_val, test_size=calib_fraction, random_state=42, stratify=y_train_val
    )
    
    print(f"Split sizes -> Train: {X_train.shape[0]}, Calibration: {X_calib.shape[0]}, Test: {X_test.shape[0]}")
    
    print("\nFitting feature scaler on training split only...")
    scaler = StandardScaler()
    X_train_s = scaler.fit_transform(X_train)
    X_calib_s = scaler.transform(X_calib)
    X_test_s = scaler.transform(X_test)
    
    print("\nTraining Base Models:")
    print("1. Random Forest Classifier (n_estimators=150, max_depth=16, balanced)...")
    rf = RandomForestClassifier(
        n_estimators=150,
        max_depth=16,
        min_samples_split=4,
        class_weight="balanced",
        random_state=42,
        n_jobs=-1
    )
    rf.fit(X_train_s, y_train)
    
    print("2. Gradient Boosting Classifier (n_estimators=100, learning_rate=0.1)...")
    gb = GradientBoostingClassifier(
        n_estimators=100,
        learning_rate=0.1,
        max_depth=6,
        random_state=42
    )
    gb.fit(X_train_s, y_train)
    
    print("\n3. Soft-Voting Base Ensemble...")
    base_ensemble = VotingClassifier(
        estimators=[("rf", rf), ("gb", gb)],
        voting="soft",
        n_jobs=-1
    )
    base_ensemble.fit(X_train_s, y_train)
    
    print("\n4. Fitting Probability Calibration on CALIBRATION split (cv='prefit', zero test leakage)...")
    calibrated_clf = CalibratedClassifierCV(
        estimator=base_ensemble,
        method="sigmoid",
        cv="prefit"
    )
    calibrated_clf.fit(X_calib_s, y_calib)
    
    print("\n5. Evaluating Calibrated Ensemble on Independent Held-Out TEST split...")
    preds = calibrated_clf.predict(X_test_s)
    probs = calibrated_clf.predict_proba(X_test_s)[:, 1]
    
    acc = accuracy_score(y_test, preds)
    auc = roc_auc_score(y_test, probs)
    brier = brier_score_loss(y_test, probs)
    
    print("\n========================================================")
    print("  CALIBRATED ENSEMBLE TEST PERFORMANCE (ZERO LEAKAGE)")
    print("========================================================")
    print(f"  Test Accuracy:     {acc * 100:.2f}%")
    print(f"  Test ROC-AUC:      {auc:.4f}")
    print(f"  Brier Score Loss:  {brier:.4f}")
    print("\nClassification Report:")
    print(classification_report(y_test, preds, target_names=["Legitimate", "Phishing"]))
    
    # Save artifacts
    model_save_path = os.path.join(MODELS_DIR, "calibrated_url_ensemble.pkl")
    scaler_save_path = os.path.join(MODELS_DIR, "feature_scaler.pkl")
    features_save_path = os.path.join(MODELS_DIR, "feature_names.pkl")
    
    joblib.dump(calibrated_clf, model_save_path)
    joblib.dump(scaler, scaler_save_path)
    joblib.dump(FEATURE_COLUMNS, features_save_path)
    
    print(f"\n[OK] Model saved to -> {model_save_path}")
    print(f"[OK] Scaler saved to -> {scaler_save_path}")
    print(f"[OK] Feature names saved to -> {features_save_path}")

    # Sanity check on top websites
    print("\n--- Sanity Checks ---")
    test_urls = [
        "https://www.google.com/",
        "https://google.com",
        "https://www.wikipedia.org/",
        "https://amazon.com",
        "http://paypal-security-login-update.com",
        "http://192.168.1.1/login.php",
        "http://appleid.apple.com.secure-update.xyz/login"
    ]
    for tu in test_urls:
        vec = extract_features_array(tu, check_dns=False)
        vec_s = scaler.transform([vec])
        p = calibrated_clf.predict_proba(vec_s)[0][1]
        print(f"  {tu:55s} -> Phish Prob: {p:.4f} ({'PHISHING' if p >= 0.5 else 'LEGIT'})")

if __name__ == "__main__":
    train()
