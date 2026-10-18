"""
train_url_model.py — Train a URL-based phishing detector
Uses the dataset from the zip file: DataFiles/5.urldata.csv
Features: Have_IP, Have_At, URL_Length, URL_Depth, Redirection,
          https_Domain, TinyURL, Prefix/Suffix, DNS_Record,
          Web_Traffic, Domain_Age, Domain_End, iFrame,
          Mouse_Over, Right_Click, Web_Forwards
Label: 0 = Legit, 1 = Phishing
"""

import os
import sys
import joblib
import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import classification_report, accuracy_score

# ── Paths ─────────────────────────────────────────────────────────────────────
SCRIPT_DIR   = os.path.dirname(os.path.abspath(__file__))
AI_DIR       = os.path.dirname(SCRIPT_DIR)
DATA_PATH    = os.path.join(AI_DIR, "..", "zip_extracted",
               "Phishing-Website-Detection-by-Machine-Learning-Techniques-master",
               "DataFiles", "5.urldata.csv")
MODELS_DIR   = os.path.join(AI_DIR, "models")
os.makedirs(MODELS_DIR, exist_ok=True)

# ── Load data ─────────────────────────────────────────────────────────────────
print("Loading dataset...")
df = pd.read_csv(DATA_PATH)
print(f"  Rows: {len(df)}  Columns: {list(df.columns)}")

# Drop the Domain column (not a feature)
if "Domain" in df.columns:
    df = df.drop(columns=["Domain"])

# Feature columns (everything except Label)
FEATURES = [c for c in df.columns if c != "Label"]
print(f"  Features ({len(FEATURES)}): {FEATURES}")

X = df[FEATURES].values
y = df["Label"].values          # 0=legit, 1=phishing

print(f"  Legit: {(y==0).sum()}  Phishing: {(y==1).sum()}")

# ── Train / test split ────────────────────────────────────────────────────────
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y)

# ── Scale ─────────────────────────────────────────────────────────────────────
scaler = StandardScaler()
X_train_s = scaler.fit_transform(X_train)
X_test_s  = scaler.transform(X_test)

# ── Train Random Forest (works with any sklearn version) ─────────────────────
print("\nTraining Random Forest…")
rf = RandomForestClassifier(
    n_estimators=200,
    max_depth=15,
    min_samples_split=5,
    class_weight="balanced",
    random_state=42,
    n_jobs=-1
)
rf.fit(X_train_s, y_train)

rf_preds = rf.predict(X_test_s)
rf_acc   = accuracy_score(y_test, rf_preds)
print(f"  Random Forest Accuracy: {rf_acc:.4f}")
print(classification_report(y_test, rf_preds, target_names=["Legit", "Phishing"]))

# ── Also try Gradient Boosting (built-in sklearn, no version issues) ──────────
print("Training Gradient Boosting…")
gb = GradientBoostingClassifier(
    n_estimators=150,
    learning_rate=0.1,
    max_depth=5,
    random_state=42
)
gb.fit(X_train_s, y_train)
gb_preds = gb.predict(X_test_s)
gb_acc   = accuracy_score(y_test, gb_preds)
print(f"  Gradient Boosting Accuracy: {gb_acc:.4f}")

# ── Pick best ─────────────────────────────────────────────────────────────────
best_model = rf if rf_acc >= gb_acc else gb
best_name  = "RandomForest" if rf_acc >= gb_acc else "GradientBoosting"
best_acc   = max(rf_acc, gb_acc)
print(f"\nBest model: {best_name}  Accuracy: {best_acc:.4f}")

# ── Save ─────────────────────────────────────────────────────────────────────
model_path   = os.path.join(MODELS_DIR, "url_detector.pkl")
scaler_path  = os.path.join(MODELS_DIR, "url_scaler.pkl")
features_path= os.path.join(MODELS_DIR, "url_features.pkl")

joblib.dump(best_model, model_path)
joblib.dump(scaler,     scaler_path)
joblib.dump(FEATURES,   features_path)

print(f"\nSaved:")
print(f"  Model    -> {model_path}")
print(f"  Scaler   -> {scaler_path}")
print(f"  Features -> {features_path}")
print("\nURL model training complete ✅")
