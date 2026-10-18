import requests
import json

test_cases = [
    ("Google Search", "https://google.com"),
    ("GitHub Root", "https://github.com"),
    ("Steam Official Store", "https://store.steampowered.com"),
    ("Adobe Behance", "https://behance.net"),
    ("Python Docs (Long URL)", "https://docs.python.org/3/library/urllib.parse.html"),
    ("Apple ID Impersonation", "http://appleid.apple.com.secure-update.xyz/login"),
    ("PayPal Phishing Portal", "http://paypal-security-login-update.com"),
    ("URLhaus Threat Intel Match", "http://59.180.137.217/i"),
    ("Unresolvable Non-existent Host", "http://unresolvable-domain-998877.xyz")
]

header = f"{'CASE':32} | {'VERDICT':12} | {'SCORE':5} | {'CONF':5} | {'INT STATE':22} | {'INTEL MATCH':11} | {'HOPS':4} | {'FINGERPRINT':16}"
print(header)
print("-" * len(header))

for name, u in test_cases:
    try:
        resp = requests.post("http://localhost:8080/api/scan", json={"url": u}, timeout=10)
        d = resp.json()
        verdict = str(d.get("verdict", "N/A"))
        score = d.get("risk_score", d.get("threat_score", 0))
        conf = round(float(d.get("confidence", 0.0)), 2)
        state = str(d.get("internal_state", "N/A"))
        intel_m = "YES" if (d.get("threat_intelligence_match") and d["threat_intelligence_match"].get("is_known_threat")) else "NO"
        hops = d.get("redirect_info", {}).get("redirect_count", 0) if d.get("redirect_info") else 0
        fp = (d.get("threat_fingerprint") or "")[:14] + ".."
        print(f"{name:32} | {verdict:12} | {score:5} | {conf:5.2f} | {state:22} | {intel_m:11} | {hops:4} | {fp:16}")
    except Exception as e:
        print(f"{name:32} | ERROR: {e}")
