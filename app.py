from flask import Flask, render_template, request
import re
from bs4 import BeautifulSoup
from urllib.parse import urlparse

app = Flask(__name__)

SUSPICIOUS_KEYWORDS = [
    "urgent", "verify", "account suspended",
    "click here", "login now", "confirm password"
]

SHORT_DOMAINS = ["bit.ly", "tinyurl.com", "t.co"]

def extract_urls(text):
    soup = BeautifulSoup(text, "html.parser")
    urls = [a["href"] for a in soup.find_all("a", href=True)]
    urls += re.findall(r'https?://\S+', text)
    return list(set(urls))

def analyze_email(text):
    score = 0
    reasons = []

    for word in SUSPICIOUS_KEYWORDS:
        if word in text.lower():
            score += 1
            reasons.append(f"Suspicious keyword: {word}")

    urls = extract_urls(text)
    for url in urls:
        domain = urlparse(url).netloc
        if any(short in domain for short in SHORT_DOMAINS):
            score += 2
            reasons.append(f"Shortened URL detected: {url}")
        if "-" in domain or domain.count(".") > 3:
            score += 1
            reasons.append(f"Suspicious domain: {domain}")

    if score >= 5:
        result = "🔴 Phishing Email"
    elif score >= 2:
        result = "🟡 Suspicious Email"
    else:
        result = "🟢 Legitimate Email"

    return result, score, reasons

@app.route("/", methods=["GET", "POST"])
def index():
    result = score = reasons = None
    if request.method == "POST":
        email = request.form["email"]
        result, score, reasons = analyze_email(email)
    return render_template("index.html",
                           result=result,
                           score=score,
                           reasons=reasons)

if __name__ == "__main__":
    app.run(debug=True)
