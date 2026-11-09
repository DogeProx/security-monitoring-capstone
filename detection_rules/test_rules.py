import unittest
from rules import analyze_response

class TestDetectionRules(unittest.TestCase):
    def setUp(self):
        self.mock_pass_response = {
            "url": "http://127.0.0.1/demo_secure",
            "status_code": 200,
            "headers": {
                "Content-Type": "text/html; charset=UTF-8",
                "Content-Security-Policy": "default-src 'self'",
                "X-Content-Type-Options": "nosniff",
                "Set-Cookie": "session_id=SECURE_TOKEN; Path=/; HttpOnly; Secure"
            }
        }
        self.mock_fail_response = {
            "url": "http://127.0.0.1/demo_vulnerable",
            "status_code": 200,
            "headers": {
                "Content-Type": "text/html",
                "Set-Cookie": "session_id=LEAKED_TOKEN; Path=/"
            }
        }

    def test_secure_response(self):
        findings = analyze_response(self.mock_pass_response)
        self.assertEqual(len(findings), 0)

    def test_vulnerable_response(self):
        findings = analyze_response(self.mock_fail_response)
        self.assertEqual(len(findings), 3)
        rule_ids = [f["rule_id"] for f in findings]
        self.assertIn("SEC-HDR-CSP", rule_ids)
        self.assertIn("SEC-HDR-XCTO", rule_ids)
        self.assertIn("SEC-CKI-HTTPONLY", rule_ids)

if __name__ == '__main__':
    unittest.main()
