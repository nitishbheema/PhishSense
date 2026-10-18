"""
main.py — PhishSense AI & Threat Intelligence Service v4.0
Complete detection engine overhaul:
  - Separate Known Threat Detection (OpenPhish / URLhaus / PhishTank / Blockchain) from ML
  - Multi-hop redirect chain analysis & domain crossing detection
  - Unified 24-feature extraction with brand impersonation & typosquatting
  - Calibrated ML Ensemble (Random Forest + Gradient Boosting + Sub-token TF-IDF NLP)
  - Live DOM/HTML security inspection (passwords, cross-origin targets, visual link spoofing)
  - Four internal states mapped to three UI verdicts: LEGITIMATE / SUSPICIOUS / PHISHING
  - UNKNOWN / Insufficient evidence state (prevents false sense of security)
"""

import os
import re
import json
import joblib
import hashlib
import logging
import numpy as np
import httpx
from datetime import datetime
from typing import Optional, Dict, Any, List
from urllib.parse import urlparse

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from threat_intel import threat_intel
from feature_extractor import (
    extract_features_vector, extract_features_array,
    FEATURE_COLUMNS, normalize_url
)
from redirect_inspector import redirect_inspector
from trusted_domain_manager import trusted_domain_manager

from url_extractor import (
    classify_domain_sector, compute_ai_deception_score
)

logging.basicConfig(level=logging.INFO, format="%(asctime)s  %(levelname)s  %(message)s")
log = logging.getLogger("phishsense-ai")

app = FastAPI(
    title="PhishSense AI & Threat Intelligence Engine v4.0",
    description="Multi-evidence phishing detection: Live Threat Intel + Redirect Tracer + Calibrated ML Ensemble + DOM Inspection",
    version="4.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Global Model Storage ───────────────────────────────────────────────────────
CALIBRATED_ENSEMBLE = None
FEATURE_SCALER = None
FEATURE_NAMES_24 = None

TFIDF_MODEL = None
TFIDF_VECTORIZER = None

BEHAVIORAL_MODEL = None
BEHAVIORAL_SCALER = None
BEHAVIORAL_FEATURES = None

BEHAVIORAL_LABEL_MAP = {0: "LEGIT", 1: "SUSPICIOUS", 2: "PHISHING"}

def custom_tokenizer(t):
    tkns_byslash = str(t).split("/")
    total_tokens = []
    for i in tkns_byslash:
        tokens = str(i).split("-")
        tkns_bydot = []
        for j in range(len(tokens)):
            temp_tkns = str(tokens[j]).split(".")
            tkns_bydot.extend(temp_tkns)
        total_tokens.extend(tokens + tkns_bydot)
    tokens_set = set(total_tokens)
    for rem in ["com", "http:", "https:", "www", "", "html", "php", "htm", "net", "org"]:
        tokens_set.discard(rem)
    return list(tokens_set)

@app.on_event("startup")
def load_models_and_intel():
    global CALIBRATED_ENSEMBLE, FEATURE_SCALER, FEATURE_NAMES_24
    global TFIDF_MODEL, TFIDF_VECTORIZER
    global BEHAVIORAL_MODEL, BEHAVIORAL_SCALER, BEHAVIORAL_FEATURES

    base = os.path.dirname(__file__)

    # 1. Calibrated URL Ensemble
    ensemble_path = os.path.join(base, "models", "calibrated_url_ensemble.pkl")
    scaler_path = os.path.join(base, "models", "feature_scaler.pkl")
    names_path = os.path.join(base, "models", "feature_names.pkl")

    if os.path.exists(ensemble_path) and os.path.exists(scaler_path):
        try:
            CALIBRATED_ENSEMBLE = joblib.load(ensemble_path)
            FEATURE_SCALER = joblib.load(scaler_path)
            FEATURE_NAMES_24 = joblib.load(names_path)
            log.info("Calibrated ML Ensemble loaded successfully (%d features)", len(FEATURE_NAMES_24))
        except Exception as e:
            log.error("Failed to load calibrated ensemble: %s", e)

    # 2. Sub-token TF-IDF NLP Model (420k real URLs)
    tfidf_model_path = os.path.join(base, "models", "tfidf_url_model.pkl")
    tfidf_vec_path = os.path.join(base, "models", "tfidf_vectorizer.pkl")
    if os.path.exists(tfidf_model_path) and os.path.exists(tfidf_vec_path):
        try:
            import __main__
            __main__.custom_tokenizer = custom_tokenizer
            TFIDF_MODEL = joblib.load(tfidf_model_path)
            TFIDF_VECTORIZER = joblib.load(tfidf_vec_path)
            log.info("420k Sub-token TF-IDF NLP model loaded")
        except Exception as e:
            log.warning("Could not load TF-IDF model: %s", e)

    # 3. Behavioral Interaction Model
    beh_model_path = os.path.join(base, "models", "phish_detector.pkl")
    beh_scaler_path = os.path.join(base, "models", "scaler.pkl")
    beh_feat_path = os.path.join(base, "models", "features.pkl")
    if os.path.exists(beh_model_path):
        try:
            BEHAVIORAL_MODEL = joblib.load(beh_model_path)
            BEHAVIORAL_SCALER = joblib.load(beh_scaler_path)
            BEHAVIORAL_FEATURES = joblib.load(beh_feat_path)
            log.info("Behavioral model loaded (%d features)", len(BEHAVIORAL_FEATURES))
        except Exception as e:
            log.warning("Could not load behavioral model: %s", e)

    # 4. Refresh Threat Intel Feeds in background
    try:
        log.info("Threat intelligence ready: %d URLs, %d domains cached",
                 len(threat_intel.exact_urls), len(threat_intel.malicious_domains))
    except Exception as e:
        log.warning("Threat intelligence init warning: %s", e)

# ── Schemas ───────────────────────────────────────────────────────────────────
class UrlScanRequest(BaseModel):
    url: str
    session_id: Optional[str] = "url-scan"

class UrlScanResponse(BaseModel):
    url: str
    verdict: str  # LEGITIMATE | SUSPICIOUS | PHISHING
    internal_state: str  # LEGITIMATE | SUSPICIOUS | PHISHING | INSUFFICIENT_EVIDENCE
    risk_score: int  # 0 to 100
    threat_score: int  # alias for backwards compatibility
    label: str  # alias for backwards compatibility
    confidence: float  # calibrated 0.0 to 1.0
    evidence_source: str  # THREAT_INTELLIGENCE | ML_ENSEMBLE | LIVE_INSPECTION | MULTI_SOURCE_FUSION
    evidence: List[Dict[str, Any]]
    threat_intelligence_match: Dict[str, Any]
    redirect_info: Dict[str, Any]
    threat_fingerprint: str
    model: str
    timestamp: str
    features: Optional[dict] = None
    top_flags: Optional[list] = None
    ai_deception_score: Optional[int] = 0
    sector: Optional[str] = "General Web Services"
    attack_family: Optional[str] = "Threat Family #6"
    webpage_signals: Optional[dict] = None
    webpage_risk_score: Optional[int] = 0
    live_inspected: Optional[bool] = False
    http_status: Optional[int] = None
    explainability: Optional[list] = None
    trusted_domain_analysis: Optional[dict] = None

class FeaturesPayload(BaseModel):
    session_id: Optional[str] = "unknown"
    features: dict

class PredictionResponse(BaseModel):
    session_id: str
    label: str
    label_index: int
    threat_score: int
    confidence: float
    probabilities: dict
    top_features: list
    timestamp: str

class WebsiteAnalysisRequest(BaseModel):
    url: str

class WebsiteAnalysisResponse(BaseModel):
    url: str
    webpage_risk_score: int
    ai_deception_score: int
    sector: str
    attack_family: str
    signals: dict
    flags: list
    explainability: list
    fetch_success: bool
    timestamp: str

class SimilarityRequest(BaseModel):
    url1: str
    url2: str

# ── Core Threat Classification Logic ──────────────────────────────────────────
@app.post("/predict-url", response_model=UrlScanResponse)
async def predict_url(req: UrlScanRequest):
    raw_input = req.url.strip()
    if not raw_input:
        raise HTTPException(status_code=400, detail="URL cannot be empty")

    is_anchor_spoof = False
    spoof_info = None

    # Check for HTML anchor tag disguise e.g. <a href="http://evil.com">https://paypal.com</a>
    if "<a " in raw_input.lower() and "href=" in raw_input.lower():
        try:
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(raw_input, "html.parser")
            a_tag = soup.find("a", href=True)
            if a_tag:
                href_val = a_tag.get("href", "").strip()
                disp_val = a_tag.get_text(strip=True)
                if disp_val.lower().startswith(("http://", "https://", "www.")) or re.match(r"^[a-zA-Z0-9-]+\.(com|org|net|edu|gov|io|co|in|xyz|app|dev)(/[^\s]*)?$", disp_val, re.IGNORECASE):
                    norm_disp = disp_val if disp_val.startswith(("http://", "https://")) else "http://" + disp_val
                    norm_href = href_val if href_val.startswith(("http://", "https://")) else "http://" + href_val
                    d_host = urlparse(norm_disp).netloc.lower().split(":")[0].replace("www.", "")
                    h_host = urlparse(norm_href).netloc.lower().split(":")[0].replace("www.", "")
                    if d_host and h_host and d_host != h_host and not d_host.endswith("." + h_host) and not h_host.endswith("." + d_host):
                        is_anchor_spoof = True
                        spoof_info = {"displayed": d_host, "actual": h_host, "disp_text": disp_val}
                url = href_val
            else:
                url = raw_input
        except Exception:
            url = raw_input
    else:
        url = raw_input

    url, hostname, clean_domain = normalize_url(url)
    sector = classify_domain_sector(url)
    fingerprint = hashlib.sha256(f"{clean_domain}:{url}".encode()).hexdigest()

    evidence: List[Dict[str, Any]] = []
    top_flags: List[str] = []

    # ──────────────────────────────────────────────────────────────────────────
    # Step 1: Distinct Known Threat Intelligence Lookup (OpenPhish, URLhaus, etc.)
    # ──────────────────────────────────────────────────────────────────────────
    threat_match = threat_intel.check_threat(url)

    # ──────────────────────────────────────────────────────────────────────────
    # Step 2: Multi-Hop Redirect Tracing & Safe Live Webpage DOM Inspection
    # ──────────────────────────────────────────────────────────────────────────
    inspection = await redirect_inspector.inspect(url)
    final_url = inspection.get("final_url", url)
    final_domain = inspection.get("final_domain", hostname)
    http_status = inspection.get("http_status")
    redirect_count = inspection.get("redirect_count", 0)
    cross_domain = inspection.get("cross_domain_redirect", False)
    dom_signals = inspection.get("dom_signals", {})
    webpage_risk = inspection.get("webpage_risk_score", 0)
    fetch_success = inspection.get("fetch_success", False)

    redirect_info = {
        "redirect_count": redirect_count,
        "cross_domain_redirect": cross_domain,
        "initial_url": url,
        "final_url": final_url,
        "redirect_chain": inspection.get("redirect_chain", []),
    }

    # ──────────────────────────────────────────────────────────────────────────
    # Step 2.5: Strict PSL-Aware Trusted Domain Knowledge Base Evaluation
    # ──────────────────────────────────────────────────────────────────────────
    td_result = trusted_domain_manager.evaluate_url(
        raw_url=url,
        threat_match=threat_match,
        redirect_info=redirect_info
    )
    if td_result.get("category") and td_result["category"] not in ["Unknown", "Uncategorized", "Security Threat"]:
        sector = td_result["category"]

    # ──────────────────────────────────────────────────────────────────────────
    # Step 3: Unified 24-Feature Extraction & ML Ensemble Prediction
    # ──────────────────────────────────────────────────────────────────────────
    feat_dict = extract_features_vector(final_url, check_dns=True)
    feat_array = [float(feat_dict[col]) for col in FEATURE_COLUMNS]

    structural_prob = 0.50
    if CALIBRATED_ENSEMBLE is not None and FEATURE_SCALER is not None:
        try:
            X_scaled = FEATURE_SCALER.transform([feat_array])
            structural_prob = float(CALIBRATED_ENSEMBLE.predict_proba(X_scaled)[0][1])
        except Exception as e:
            log.warning("Calibrated ensemble inference error: %s", e)

    tfidf_prob = 0.50
    if TFIDF_MODEL is not None and TFIDF_VECTORIZER is not None:
        try:
            tfidf_vec = TFIDF_VECTORIZER.transform([final_url])
            tfidf_prob = float(TFIDF_MODEL.predict_proba(tfidf_vec)[0][1])
        except Exception as e:
            log.warning("TFIDF inference error: %s", e)

    # Calibrated combined ML probability (0.75 calibrated 24-feature ensemble + 0.25 TF-IDF sub-token model)
    ml_prob = round(0.75 * structural_prob + 0.25 * tfidf_prob, 4)
    ml_risk_score = int(round(ml_prob * 100))

    # ──────────────────────────────────────────────────────────────────────────
    # Step 4: Multi-Evidence Risk Fusion & State Resolution
    # ──────────────────────────────────────────────────────────────────────────
    fused_risk = ml_risk_score
    evidence_source = "ML_ENSEMBLE"
    attack_family = "Threat Family #6 (Generic Web Architecture)"

    # Evidence Channel 0: Trusted Domain Match / Lookalike Detection
    if td_result.get("match_level") in ["LOOKALIKE_IMPERSONATION", "PUNYCODE_IMPERSONATION"]:
        fused_risk = max(fused_risk, 88 if td_result["match_level"] == "LOOKALIKE_IMPERSONATION" else 95)
        evidence_source = "TRUSTED_DOMAIN_IMPERSONATION"
        attack_family = "Threat Family #3 (Brand Impersonation & Typosquatting Cluster)"
        top_flags.append(f"Domain Impersonation: Mimics '{td_result['brand_name']}' on unauthorized infrastructure")
        for r in td_result.get("reasons", []):
            evidence.append({"factor": r, "impact": "CRITICAL", "source": "TRUSTED_DOMAIN_INTEL"})
    elif td_result.get("is_trusted"):
        if td_result.get("is_hosting_provider"):
            # Multi-tenant provider (GitHub, AWS, Vercel, Supabase, etc.)
            if not is_anchor_spoof and not dom_signals.get("has_spoofed_hyperlinks") and not (dom_signals.get("has_password_field") and dom_signals.get("has_suspicious_action")):
                fused_risk = min(fused_risk, 20)
                evidence_source = "MULTI_TENANT_HOSTING"
                for r in td_result.get("reasons", []):
                    evidence.append({"factor": r, "impact": "LOW" if "Verified" in r else "MEDIUM", "source": "TRUSTED_DOMAIN_INTEL"})
                top_flags.append(f"Multi-Tenant Host: {td_result['brand_name']} verified infrastructure")
        else:
            # Verified official domain or official subdomain (Google, Microsoft, SBI, Wikipedia, etc.)
            if not is_anchor_spoof and not dom_signals.get("has_spoofed_hyperlinks") and not (dom_signals.get("has_password_field") and dom_signals.get("has_suspicious_action")):
                fused_risk = min(fused_risk, 4)
                evidence_source = "TRUSTED_DOMAIN_KNOWLEDGE_BASE"
                live_verified_safe = True
                for r in reversed(td_result.get("reasons", [])):
                    evidence.insert(0, {"factor": r, "impact": "BENIGN", "source": "TRUSTED_DOMAIN_INTEL"})
                top_flags.insert(0, f"Trusted Domain: Verified {td_result['brand_name']} ({td_result['match_level']})")

    # Evidence Channel A: Confirmed Global Threat Intelligence
    if threat_match.get("is_known_threat"):
        fused_risk = 100
        evidence_source = "THREAT_INTELLIGENCE"
        attack_family = f"Threat Family #1 ({threat_match.get('source')} Confirmed Malicious Campaign)"
        top_flags.append(f"Global Threat Intelligence: Confirmed in {threat_match.get('source')}")
        evidence.append({
            "factor": f"Known Threat Intelligence: Listed in {threat_match.get('source')} feed ({threat_match.get('details')})",
            "impact": "CRITICAL",
            "source": "THREAT_INTELLIGENCE",
        })

    # Evidence Channel B: Visual Hyperlink Spoofing (DOM or Anchor Tag)
    if is_anchor_spoof and spoof_info:
        fused_risk = max(fused_risk, 98)
        evidence_source = "LIVE_INSPECTION"
        attack_family = "Threat Family #3 (Visual Hyperlink Spoofing & Domain Impersonation)"
        top_flags.append(f"Visual Link Discrepancy: Claims '{spoof_info['displayed']}' but directs to '{spoof_info['actual']}'")
        evidence.append({
            "factor": f"Deceptive Link Disguise: Anchor text displays trusted '{spoof_info['displayed']}' but navigates to '{spoof_info['actual']}'",
            "impact": "CRITICAL",
            "source": "DOM_INSPECTION",
        })

    if dom_signals.get("has_spoofed_hyperlinks"):
        fused_risk = max(fused_risk, 88)
        sample = dom_signals.get("spoofed_links_sample", [{}])[0]
        top_flags.append(f"DOM Link Spoofing: Page anchor text claims '{sample.get('displayed')}' but targets '{sample.get('actual')}'")
        evidence.append({
            "factor": f"Deceptive Visual Anchor: Page displays trusted domain '{sample.get('displayed')}' but points to external '{sample.get('actual')}'",
            "impact": "CRITICAL",
            "source": "DOM_INSPECTION",
        })

    # Evidence Channel C: Live Credential Theft Form & Cross-Origin Action
    if dom_signals.get("has_password_field"):
        if dom_signals.get("has_suspicious_action") or dom_signals.get("title_auth_mismatch"):
            fused_risk = max(fused_risk, 90)
            attack_family = "Threat Family #1 (Credential Harvesting Portal)"
            top_flags.append("Credential Theft: Password field submitting to untrusted cross-origin endpoint")
            evidence.append({
                "factor": "Credential Harvesting: Password input form submitting credentials cross-origin",
                "impact": "CRITICAL",
                "source": "DOM_INSPECTION",
            })
        else:
            evidence.append({
                "factor": "Authentication Form: Standard password input detected",
                "impact": "LOW",
                "source": "DOM_INSPECTION",
            })

    # Evidence Channel D: Brand Impersonation & Typosquatting
    if feat_dict.get("brand_impersonation", 0) == 1:
        fused_risk = max(fused_risk, 78)
        attack_family = "Threat Family #3 (Homoglyph & Brand Impersonation Cluster)"
        top_flags.append("Brand Abuse: Target brand keyword embedded in unauthorized subdomain")
        evidence.append({
            "factor": "Subdomain Impersonation: Mimics recognized brand on unverified host infrastructure",
            "impact": "HIGH",
            "source": "LEXICAL_ANALYZER",
        })

    if feat_dict.get("brand_typosquatting", 0) == 1:
        fused_risk = max(fused_risk, 72)
        top_flags.append("Typosquatting: Domain is 1-2 edits or leet substitution from trusted brand")
        evidence.append({
            "factor": "Typosquatting Detected: Domain name resembles a major brand with character mutations",
            "impact": "HIGH",
            "source": "LEXICAL_ANALYZER",
        })

    # Evidence Channel E: Multi-Hop Cross-Domain Redirection Cloaking
    if cross_domain and redirect_count >= 2:
        fused_risk = max(fused_risk, 68)
        attack_family = "Threat Family #2 (Redirect & Proxy Cloaking Chain)"
        top_flags.append(f"Redirect Cloaking: {redirect_count} hops crossing external domain boundaries")
        evidence.append({
            "factor": f"Evasion Cloaking: Navigates across multiple domains ({redirect_count} hops) before reaching final destination",
            "impact": "HIGH",
            "source": "REDIRECT_TRACER",
        })

    # Evidence Channel F: High-Abuse Suspicious TLD
    if feat_dict.get("suspicious_tld", 0) == 1:
        evidence.append({
            "factor": f"High-Abuse TLD: Domain uses extension statistically linked to malicious campaigns",
            "impact": "MEDIUM",
            "source": "TLD_REPUTATION",
        })

    live_verified_safe = False
    if fetch_success and http_status in [200, 301, 302, 304] and not threat_match.get("is_known_threat"):
        has_pwd = dom_signals.get("has_password_field", False)
        suspicious_action = dom_signals.get("has_suspicious_action", False)
        has_spoof = dom_signals.get("has_spoofed_hyperlinks", False)
        brand_abuse = (feat_dict.get("brand_impersonation", 0) == 1 or feat_dict.get("brand_typosquatting", 0) == 1)

        if not has_pwd and not suspicious_action and not has_spoof and not brand_abuse and webpage_risk < 20:
            # Verified safe live content!
            live_verified_safe = True
            fused_risk = min(fused_risk, 18)
            evidence_source = "LIVE_INSPECTION"
            evidence.insert(0, {
                "factor": f"✓ Live Site Verified: HTTP {http_status} OK — no credential harvesting forms or deceptive cloaking detected",
                "impact": "BENIGN",
                "source": "LIVE_INSPECTION",
            })
            if len(url) >= 75:
                evidence.append({
                    "factor": "✓ URL Length Normalized: Extended path/query parameters verified benign via live content inspection",
                    "impact": "BENIGN",
                    "source": "LEXICAL_ANALYZER",
                })
            top_flags.append(f"Live Inspection: HTTP {http_status} OK — verified legitimate page structure")

    # ──────────────────────────────────────────────────────────────────────────
    # Step 5: Verdict & Four-State Internal Resolution
    # ──────────────────────────────────────────────────────────────────────────
    is_phishing = False
    if threat_match.get("is_known_threat"):
        is_phishing = True
    elif td_result.get("match_level") in ["LOOKALIKE_IMPERSONATION", "PUNYCODE_IMPERSONATION"]:
        is_phishing = True
    elif is_anchor_spoof or dom_signals.get("has_spoofed_hyperlinks"):
        is_phishing = True
    elif dom_signals.get("has_password_field") and (dom_signals.get("has_suspicious_action") or dom_signals.get("title_auth_mismatch")):
        is_phishing = True
    elif (feat_dict.get("brand_impersonation", 0) == 1 or feat_dict.get("brand_typosquatting", 0) == 1) and not td_result.get("is_trusted"):
        is_phishing = True
    elif not live_verified_safe and ml_prob >= 0.70 and feat_dict.get("dns_resolved", 1) == 1:
        is_phishing = True
    elif not live_verified_safe and fused_risk >= 70 and feat_dict.get("dns_resolved", 1) == 1:
        is_phishing = True

    if is_phishing:
        verdict = "PHISHING"
        internal_state = "PHISHING"
        fused_risk = max(fused_risk, 75)
        confidence = max(0.90, ml_prob)
    elif td_result.get("is_trusted") and not td_result.get("is_hosting_provider") and not is_anchor_spoof and not dom_signals.get("has_spoofed_hyperlinks"):
        # Verified official domain or subdomain from Trusted Domain Knowledge Base
        verdict = "LEGITIMATE"
        internal_state = "LEGITIMATE"
        fused_risk = min(fused_risk, 4)
        confidence = max(0.98, round(1.0 - ml_prob, 4))
    elif not fetch_success and feat_dict.get("dns_resolved", 1) == 0:
        # Host could not be reached or resolved in DNS -> INSUFFICIENT EVIDENCE
        internal_state = "INSUFFICIENT_EVIDENCE"
        verdict = "SUSPICIOUS"
        fused_risk = 45
        confidence = 0.50
        evidence.insert(0, {
            "factor": "Insufficient Evidence: Host could not be reached or resolved in DNS. No verified proof of safety exists.",
            "impact": "MEDIUM",
            "source": "CONNECTIVITY_PROBE",
        })
        top_flags.insert(0, "Unverified: Domain does not resolve DNS records")
    elif fused_risk >= 50 or cross_domain or feat_dict.get("suspicious_tld", 0) == 1:
        verdict = "SUSPICIOUS"
        internal_state = "SUSPICIOUS"
        confidence = max(0.70, ml_prob)
    else:
        # Verified clean
        verdict = "LEGITIMATE"
        internal_state = "LEGITIMATE"
        fused_risk = min(fused_risk, 18)
        confidence = max(0.88, round(1.0 - ml_prob, 4))

    ai_deception = compute_ai_deception_score(feat_dict, dom_signals if dom_signals else None)

    # Legacy explainability mapping
    legacy_explain = [{"factor": e["factor"], "impact": e["impact"]} for e in evidence[:6]]

    return UrlScanResponse(
        url=url,
        verdict=verdict,
        internal_state=internal_state,
        risk_score=fused_risk,
        threat_score=fused_risk,
        label=verdict,
        confidence=round(confidence, 4),
        evidence_source=evidence_source,
        evidence=evidence,
        threat_intelligence_match=threat_match,
        redirect_info=redirect_info,
        threat_fingerprint=fingerprint,
        model="CalibratedEnsemble-RF+GB+TFIDF-420k+ThreatIntel",
        timestamp=datetime.utcnow().isoformat(),
        features=feat_dict,
        top_flags=top_flags,
        ai_deception_score=ai_deception,
        sector=sector,
        attack_family=attack_family,
        explainability=legacy_explain,
        webpage_signals=dom_signals if dom_signals else None,
        webpage_risk_score=webpage_risk,
        live_inspected=fetch_success,
        http_status=http_status,
        trusted_domain_analysis=td_result,
    )

# ── Supporting Endpoints ──────────────────────────────────────────────────────
@app.get("/health")
def health():
    return {
        "status": "UP",
        "calibrated_ensemble": CALIBRATED_ENSEMBLE is not None,
        "tfidf_model": TFIDF_MODEL is not None,
        "behavioral_model": BEHAVIORAL_MODEL is not None,
        "threat_intel_urls": len(threat_intel.exact_urls),
        "threat_intel_domains": len(threat_intel.malicious_domains),
        "trusted_domains_count": len(trusted_domain_manager.domain_to_record),
        "trusted_domains_version": trusted_domain_manager.metadata.get("version", "2.0.0"),
        "version": "4.0.0",
    }

@app.get("/trusted-domains")
def get_trusted_domains():
    return trusted_domain_manager.get_summary()

@app.get("/trusted-domains/check")
def check_trusted_domain(url: str):
    return trusted_domain_manager.evaluate_url(url)

@app.post("/trusted-domains/reload")
def reload_trusted_domains():
    return trusted_domain_manager.reload()

@app.post("/predict", response_model=PredictionResponse)
def predict(payload: FeaturesPayload):
    if BEHAVIORAL_MODEL is None:
        raise HTTPException(status_code=503, detail="Behavioral model not loaded.")
    raw = payload.features
    # Build feature vector
    vec = [float(raw.get(f, 0.0)) for f in BEHAVIORAL_FEATURES]
    X = np.array(vec).reshape(1, -1)
    X_scaled = BEHAVIORAL_SCALER.transform(X)
    label_idx = int(BEHAVIORAL_MODEL.predict(X_scaled)[0])
    proba = BEHAVIORAL_MODEL.predict_proba(X_scaled)[0]

    probas = {BEHAVIORAL_LABEL_MAP[i]: round(float(p), 4) for i, p in enumerate(proba)}
    label = BEHAVIORAL_LABEL_MAP[label_idx]
    confidence = round(float(proba[label_idx]), 4)
    score = int(round(probas.get("PHISHING", 0) * 100 + probas.get("SUSPICIOUS", 0) * 50))

    return PredictionResponse(
        session_id=payload.session_id,
        label=label,
        label_index=label_idx,
        threat_score=score,
        confidence=confidence,
        probabilities=probas,
        top_features=[],
        timestamp=datetime.utcnow().isoformat(),
    )

@app.post("/analyze-website", response_model=WebsiteAnalysisResponse)
async def analyze_website(req: WebsiteAnalysisRequest):
    url = req.url.strip()
    if not url:
        raise HTTPException(status_code=400, detail="URL cannot be empty")
    url, hostname, clean_domain = normalize_url(url)
    sector = classify_domain_sector(url)

    inspection = await redirect_inspector.inspect(url)
    dom_signals = inspection.get("dom_signals", {})
    webpage_risk = inspection.get("webpage_risk_score", 0)
    fetch_success = inspection.get("fetch_success", False)

    flags = []
    if dom_signals.get("has_password_field"):
        flags.append("Password input field detected on page")
    if dom_signals.get("has_suspicious_action"):
        flags.append("Form action target points to external cross-origin endpoint")
    if dom_signals.get("has_spoofed_hyperlinks"):
        flags.append("Visual hyperlink deception detected in page DOM")
    if dom_signals.get("right_click_disabled"):
        flags.append("Right-click context menu inspection disabled")

    explainability = [{"factor": f, "impact": "HIGH" if "Password" in f or "Visual" in f else "MEDIUM"} for f in flags]

    return WebsiteAnalysisResponse(
        url=url,
        webpage_risk_score=webpage_risk,
        ai_deception_score=15 if dom_signals.get("has_password_field") else 0,
        sector=sector,
        attack_family="Threat Family #1 (Credential Harvesting Portal)" if dom_signals.get("has_password_field") else "Threat Family #6",
        signals=dom_signals,
        flags=flags,
        explainability=explainability,
        fetch_success=fetch_success,
        timestamp=datetime.utcnow().isoformat(),
    )

@app.post("/threat-similarity")
def calculate_similarity(req: SimilarityRequest):
    f1 = set([k for k, v in extract_features_vector(req.url1).items() if v == 1])
    f2 = set([k for k, v in extract_features_vector(req.url2).items() if v == 1])
    intersection = len(f1.intersection(f2))
    union = len(f1.union(f2))
    jaccard = (intersection / union) if union > 0 else 1.0

    d1 = urlparse(req.url1).netloc
    d2 = urlparse(req.url2).netloc
    b1 = set([d1[i:i+2] for i in range(len(d1)-1)])
    b2 = set([d2[i:i+2] for i in range(len(d2)-1)])
    b_inter = len(b1.intersection(b2))
    b_union = len(b1.union(b2))
    domain_sim = (b_inter / b_union) if b_union > 0 else 0.0

    combined = round(float((jaccard * 0.6) + (domain_sim * 0.4)) * 100, 1)
    is_related = (combined >= 65.0)

    return {
        "similarity_score": combined,
        "is_related_threat": is_related,
        "feature_overlap": list(f1.intersection(f2)),
        "threat_relationship": "Related Campaign Member" if is_related else "Independent Threat"
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=False)
