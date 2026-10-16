
import re
from urllib.parse import urlparse


SUSPICIOUS_PHRASES = [
    "verify your account immediately",
    "your account will be suspended",
    "urgent action required",
    "confirm your password",
    "click here to avoid suspension",
    "claim your prize",
]

URL_PATTERN = re.compile(r"https?://[^\s<>\"']+", re.IGNORECASE)


def analyze_phishing(email_data):
    """Identify basic phishing indicators in parsed email data."""

    findings = []
    text = (
        f"{email_data.get('subject', '')}\n"
        f"{email_data.get('body', '')}"
    ).lower()

    for phrase in SUSPICIOUS_PHRASES:
        if phrase in text:
            findings.append({
                "indicator": "Suspicious wording",
                "details": f"Found phrase: '{phrase}'",
                "points": 2,
            })

    urls = URL_PATTERN.findall(
        f"{email_data.get('subject', '')}\n"
        f"{email_data.get('body', '')}"
    )

    for raw_url in urls:
        cleaned_url = raw_url.rstrip(".,);]")
        parsed = urlparse(cleaned_url)
        hostname = (parsed.hostname or "").lower()

        if not hostname:
            findings.append({
                "indicator": "Malformed URL",
                "details": f"Could not identify hostname in: {cleaned_url}",
                "points": 2,
            })
            continue

        if parsed.scheme.lower() == "http":
            findings.append({
                "indicator": "Unencrypted URL",
                "details": f"URL uses HTTP: {cleaned_url}",
                "points": 1,
            })

        if hostname.startswith("xn--") or ".xn--" in hostname:
            findings.append({
                "indicator": "Internationalized domain",
                "details": f"Review domain for possible lookalike characters: {hostname}",
                "points": 2,
            })

        if "@" in parsed.netloc:
            findings.append({
                "indicator": "URL contains @ symbol",
                "details": f"Review URL carefully: {cleaned_url}",
                "points": 2,
            })

    score = min(sum(item["points"] for item in findings), 10)

    if score >= 6:
        risk = "High"
    elif score >= 3:
        risk = "Medium"
    else:
        risk = "Low"

    return {
        "risk_score": score,
        "risk_level": risk,
        "findings": findings,
        "urls_found": [
            url.rstrip(".,);]") for url in urls
        ],
    }


if __name__ == "__main__":
    demo_email = {
        "subject": "Urgent action required",
        "body": (
            "Your account will be suspended. "
            "Confirm your password at http://example.com/login"
        ),
    }

    result = analyze_phishing(demo_email)

    print("===== PHISHGUARD DETECTION TEST =====")
    print(f"Risk score: {result['risk_score']}/10")
    print(f"Risk level: {result['risk_level']}")
    print(f"URLs found: {result['urls_found']}")

    for finding in result["findings"]:
        print(f"- {finding['indicator']}: {finding['details']}")
