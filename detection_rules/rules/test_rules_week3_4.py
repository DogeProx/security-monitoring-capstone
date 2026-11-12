import unittest
from rules import analyze_response
from integration import process_scan_report

class TestDetectionRulesAdvanced(unittest.TestCase):
    def setUp(self):
        # Ca 1: API JSON (Không có cookie, Content-Type là application/json)
        self.mock_json_response = {
            "scan_id": "1234-abcd",
            "url": "http://127.0.0.1/api/data",
            "status": "completed",
            "status_code": 200,
            "headers": {
                "Content-Type": "application/json",
            } # Báo sai (false positive) nếu bắt CSP ở đây
        }
        
        # Ca 2: Web HTML nhưng KHÔNG ĐẶT cookie phiên
        self.mock_no_cookie_response = {
            "scan_id": "1234-abcd",
            "url": "http://127.0.0.1/demo_no_cookie",
            "status": "completed",
            "status_code": 200,
            "headers": {
                "Content-Type": "text/html",
                # Báo lỗi CSP và XCTO, nhưng không lỗi Cookie
            }
        }

    def test_json_api_false_positive(self):
        findings = analyze_response(self.mock_json_response)
        rule_ids = [f["rule_id"] for f in findings]
        
        # Kỳ vọng: KHÔNG dính SEC-HDR-CSP (vì là JSON), chỉ dính SEC-HDR-XCTO
        self.assertNotIn("SEC-HDR-CSP", rule_ids)
        self.assertIn("SEC-HDR-XCTO", rule_ids)
        self.assertNotIn("SEC-CKI-HTTPONLY", rule_ids)

    def test_missing_session_cookie(self):
        findings = analyze_response(self.mock_no_cookie_response)
        rule_ids = [f["rule_id"] for f in findings]
        
        # Kỳ vọng: Thiếu CSP, thiếu XCTO, nhưng KHÔNG bắt lỗi Cookie vì server ko tạo
        self.assertIn("SEC-HDR-CSP", rule_ids)
        self.assertIn("SEC-HDR-XCTO", rule_ids)
        self.assertNotIn("SEC-CKI-HTTPONLY", rule_ids)

    def test_rule_toggle_config(self):
        # Tắt quy tắc XCTO, chỉ bật CSP
        custom_config = {
            "SEC-HDR-CSP": True,
            "SEC-HDR-XCTO": False, 
            "SEC-CKI-HTTPONLY": False
        }
        findings = analyze_response(self.mock_no_cookie_response, config=custom_config)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["rule_id"], "SEC-HDR-CSP")

if __name__ == '__main__':
    unittest.main()