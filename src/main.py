
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

from email_analyzer import analyze_email
from phishing_detector import analyze_phishing


PROJECT_ROOT = Path(__file__).resolve().parent.parent
REPORT_DIR = PROJECT_ROOT / "reports"


def main():
    if len(sys.argv) > 2:
        print("Usage: python src/main.py [path-to-email.eml]")
        return 2

    email_path = (
        Path(sys.argv[1])
        if len(sys.argv) == 2
        else PROJECT_ROOT / "samples" / "sample_email.eml"
    )

    if not email_path.is_absolute():
        email_path = PROJECT_ROOT / email_path

    try:
        email_data = analyze_email(email_path)
        result = analyze_phishing(email_data)
    except (OSError, ValueError) as error:
        print(f"Analysis failed: {error}")
        return 1

    report = {
        "analyzed_at": datetime.now(timezone.utc).isoformat(),
        "file": email_path.name,
        "sender": email_data["sender"],
        "recipient": email_data["recipient"],
        "subject": email_data["subject"],
        **result,
    }

    REPORT_DIR.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_path = REPORT_DIR / f"phishguard_report_{timestamp}.json"

    try:
        report_path.write_text(
            json.dumps(report, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
    except OSError as error:
        print(f"Could not save report: {error}")
        return 1

    print("\n===== PHISHGUARD EMAIL ANALYSIS =====")
    print(f"File: {email_path.name}")
    print(f"Sender: {email_data['sender']}")
    print(f"Subject: {email_data['subject']}")
    print(f"Risk score: {result['risk_score']}/10")
    print(f"Risk level: {result['risk_level']}")
    print(f"URLs found: {len(result['urls_found'])}")

    if result["findings"]:
        print("\nIndicators:")
        for finding in result["findings"]:
            print(f"- {finding['indicator']}: {finding['details']}")
    else:
        print("\nNo configured phishing indicators were detected.")

    print(f"\nJSON report saved: {report_path}")
    print("\nNote: This heuristic is not proof that an email is malicious or safe.")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
