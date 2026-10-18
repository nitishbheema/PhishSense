"""
train_model.py
Trains and evaluates:
  1. Random Forest classifier
  2. XGBoost classifier
  3. Soft-voting Ensemble (RF + XGB)

Saves the best model to models/phish_detector.pkl
Also saves the scaler and label encoder.
"""

import os
import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier, VotingClassifier
from sklearn.model_selection import train_test_split, cross_val_score, StratifiedKFold
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.metrics import (
    classification_report, confusion_matrix,
    accuracy_score, roc_auc_score
)
from xgboost import XGBClassifier

# ── Config ───────────────────────────────────────────────────────────────────

FEATURES = [
    "mouse_point_count", "mouse_jitter", "avg_mouse_speed",
    "keystroke_count", "typing_speed_cps", "backspace_count", "paste_count",
    "typing_delay_mean", "typing_delay_stddev",
    "click_count", "rapid_clicks",
    "total_active_ms", "frontend_anomaly_score",
]

LABEL_NAMES = {0: "LEGIT", 1: "SUSPICIOUS", 2: "PHISHING"}

# ── Load Data ─────────────────────────────────────────────────────────────────

print("=" * 60)
print("PhishGuard AI — Model Training")
print("=" * 60)

df = pd.read_csv("data/behavioral_dataset.csv")
print(f"\nDataset: {len(df)} samples")
print(df["label"].value_counts().rename(LABEL_NAMES))

X = df[FEATURES].values
y = df["label"].values

# ── Preprocessing ─────────────────────────────────────────────────────────────

scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)

X_train, X_test, y_train, y_test = train_test_split(
    X_scaled, y, test_size=0.2, random_state=42, stratify=y
)
print(f"\nTrain: {len(X_train)}  Test: {len(X_test)}")

# ── Models ────────────────────────────────────────────────────────────────────

rf = RandomForestClassifier(
    n_estimators=200,
    max_depth=12,
    min_samples_split=5,
    min_samples_leaf=2,
    class_weight="balanced",
    random_state=42,
    n_jobs=-1,
)

xgb = XGBClassifier(
    n_estimators=200,
    max_depth=6,
    learning_rate=0.1,
    subsample=0.8,
    colsample_bytree=0.8,
    use_label_encoder=False,
    eval_metric="mlogloss",
    random_state=42,
    verbosity=0,
)

ensemble = VotingClassifier(
    estimators=[("rf", rf), ("xgb", xgb)],
    voting="soft",
    weights=[1, 1],
)

# ── Train & Evaluate ──────────────────────────────────────────────────────────

results = {}

for name, model in [("Random Forest", rf), ("XGBoost", xgb), ("Ensemble (RF+XGB)", ensemble)]:
    print(f"\n── {name} ──")

    # Cross-validation
    cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
    cv_scores = cross_val_score(model, X_scaled, y, cv=cv, scoring="accuracy", n_jobs=-1)
    print(f"  CV Accuracy: {cv_scores.mean():.4f} ± {cv_scores.std():.4f}")

    # Train on full train set
    model.fit(X_train, y_train)
    y_pred = model.predict(X_test)
    y_proba = model.predict_proba(X_test)

    acc = accuracy_score(y_test, y_pred)
    auc = roc_auc_score(y_test, y_proba, multi_class="ovr", average="macro")
    print(f"  Test Accuracy: {acc:.4f}  |  AUC-ROC: {auc:.4f}")
    print(classification_report(y_test, y_pred, target_names=["LEGIT", "SUSPICIOUS", "PHISHING"]))

    results[name] = {"model": model, "accuracy": acc, "auc": auc}

# ── Feature Importance (RF) ───────────────────────────────────────────────────

print("\n── Feature Importance (Random Forest) ──")
rf_fitted = results["Random Forest"]["model"]
importances = sorted(
    zip(FEATURES, rf_fitted.feature_importances_),
    key=lambda x: x[1], reverse=True
)
for feat, imp in importances:
    bar = "█" * int(imp * 50)
    print(f"  {feat:<28} {imp:.4f}  {bar}")

# ── Save Best Model ───────────────────────────────────────────────────────────

best_name = max(results, key=lambda k: results[k]["accuracy"])
best_model = results[best_name]["model"]
print(f"\nBest model: {best_name}  (acc={results[best_name]['accuracy']:.4f})")

os.makedirs("models", exist_ok=True)

joblib.dump(best_model, "models/phish_detector.pkl")
joblib.dump(scaler,     "models/scaler.pkl")
joblib.dump(FEATURES,   "models/features.pkl")

print("Saved:")
print("  models/phish_detector.pkl")
print("  models/scaler.pkl")
print("  models/features.pkl")
print("\nTraining complete! 🎯")
