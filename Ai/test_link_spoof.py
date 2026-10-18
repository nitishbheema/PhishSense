import re
from urllib.parse import urlparse
from bs4 import BeautifulSoup

def inspect_hyperlink_spoofing(html_or_text: str):
    soup = BeautifulSoup(html_or_text, "html.parser")
    anchors = soup.find_all("a", href=True)
    spoofed = []
    for a in anchors:
        href = a.get("href", "").strip()
        disp = a.get_text(strip=True)
        if re.search(r"[a-zA-Z0-9-]+\.[a-zA-Z]{2,}", disp):
            norm_disp = disp if disp.startswith(("http://", "https://")) else "http://" + disp
            norm_href = href if href.startswith(("http://", "https://")) else "http://" + href
            try:
                d_host = urlparse(norm_disp).netloc.lower()
                h_host = urlparse(norm_href).netloc.lower()
                if d_host and h_host and d_host != h_host:
                    spoofed.append({
                        "displayed_domain": d_host,
                        "actual_destination": h_host,
                        "display_text": disp
                    })
            except Exception:
                pass
    return spoofed

test_html = '<p>Verify your account: <a href="http://evil-attacker.xyz/login.php">https://paypal.com/signin</a> immediately.</p>'
print("Spoofing result:", inspect_hyperlink_spoofing(test_html))
