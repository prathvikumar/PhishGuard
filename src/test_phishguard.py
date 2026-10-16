
import unittest

from phishing_detector import analyze_phishing


class PhishingDetectorTests(unittest.TestCase):

    def test_normal_email_has_low_risk(self):
        email = {
            "subject": "Password Security Reminder",
            "body": (
                "Please review your account security settings. "
                "Visit https://example.com/security for information."
            ),
        }

        result = analyze_phishing(email)

        self.assertEqual(result["risk_score"], 0)
        self.assertEqual(result["risk_level"], "Low")
        self.assertEqual(result["findings"], [])

    def test_suspicious_email_has_high_risk(self):
        email = {
            "subject": "URGENT: Your account will be suspended",
            "body": (
                "Urgent action required! "
                "Confirm your password at "
                "http://example.com/verify"
            ),
        }

        result = analyze_phishing(email)

        self.assertGreaterEqual(result["risk_score"], 6)
        self.assertEqual(result["risk_level"], "High")
        self.assertTrue(result["findings"])
        self.assertIn(
            "http://example.com/verify",
            result["urls_found"],
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
