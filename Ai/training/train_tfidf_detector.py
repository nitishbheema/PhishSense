"""
train_tfidf_detector.py — Trains an NLP Lexical Sub-Token TF-IDF URL detector
using the 420,464 URL dataset from Fake-URL-Detector-main.zip.
"""

import os
import shutil
import joblib
import pandas as pd
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score, roc_auc_score

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
AI_DIR = os.path.dirname(SCRIPT_DIR)
SOURCE_CSV = os.path.join(AI_DIR, "..", "zip_extracted", "Fake-URL-Detector-main", "Fake-URL-Detector-main", "urls.csv")
TARGET_CSV = os.path.join(AI_DIR, "data", "urls_420k.csv")
MODELS_DIR = os.path.join(AI_DIR, "models")
os.makedirs(MODELS_DIR, exist_ok=True)
os.makedirs(os.path.join(AI_DIR, "data"), exist_ok=True)

# 1. Preserve dataset inside Ai/data
if os.path.exists(SOURCE_CSV) and not os.path.exists(TARGET_CSV):
    print("Copying 420k URLs dataset to Ai/data/urls_420k.csv...")
    shutil.copyfile(SOURCE_CSV, TARGET_CSV)

DATA_PATH = TARGET_CSV if os.path.exists(TARGET_CSV) else SOURCE_CSV

def custom_tokenizer(t):
    tkns_byslash = str(t).split('/')
    total_tokens = []
    for i in tkns_byslash:
        tokens = str(i).split('-')
        tkns_bydot = []
        for j in range(len(tokens)):
            temp_tkns = str(tokens[j]).split('.')
            tkns_bydot.extend(temp_tkns)
        total_tokens.extend(tokens + tkns_bydot)
    tokens_set = set(total_tokens)
    for rem in ['com', 'http:', 'https:', 'www', '', 'html', 'php', 'htm', 'net', 'org']:
        tokens_set.discard(rem)
    return list(tokens_set)

print(f"Loading URL dataset from {DATA_PATH}...")
df = pd.read_csv(DATA_PATH)
print(f"Loaded {len(df)} URLs. Distribution:")
print(df['label'].value_counts())

good_df = df[df['label'] == 'good']
bad_df = df[df['label'] == 'bad']

# Balanced sampling up to 75,000 per class (150,000 URLs) for optimal speed and generalization
n_samples = min(75000, len(bad_df))
sample_good = good_df.sample(n=n_samples, random_state=42)
sample_bad = bad_df.sample(n=n_samples, random_state=42)
train_df = pd.concat([sample_good, sample_bad]).sample(frac=1.0, random_state=42).reset_index(drop=True)

X_text = train_df['url']
y = (train_df['label'] == 'bad').astype(int).values

X_train_txt, X_test_txt, y_train, y_test = train_test_split(
    X_text, y, test_size=0.15, random_state=42, stratify=y
)

print(f"\nVectorizing {len(X_train_txt)} URLs with TF-IDF sub-token n-grams...")
vec = TfidfVectorizer(tokenizer=custom_tokenizer, max_features=30000, ngram_range=(1, 2))
X_train = vec.fit_transform(X_train_txt)
X_test = vec.transform(X_test_txt)

print("Training Calibrated Logistic Classifier...")
clf = LogisticRegression(C=3.5, max_iter=1000, solver='lbfgs', n_jobs=-1)
clf.fit(X_train, y_train)

preds = clf.predict(X_test)
probs = clf.predict_proba(X_test)[:, 1]

acc = accuracy_score(y_test, preds)
auc = roc_auc_score(y_test, probs)

print(f"\nModel Performance on Test Split ({len(y_test)} URLs):")
print(f"  Accuracy: {acc*100:.2f}%")
print(f"  ROC-AUC:  {auc:.4f}")
print(classification_report(y_test, preds, target_names=['Legit', 'Phishing/Malicious']))

# Save trained models
vec_path = os.path.join(MODELS_DIR, "tfidf_vectorizer.pkl")
model_path = os.path.join(MODELS_DIR, "tfidf_url_model.pkl")

print(f"Saving vectorizer to {vec_path}...")
joblib.dump(vec, vec_path)
print(f"Saving classifier to {model_path}...")
joblib.dump(clf, model_path)

print("TF-IDF URL detector training completed successfully!")
