import unittest
from detection_rules.rules import analyze_response

SEVERITY_LEVELS = {
    "Low": 1,
    "Medium": 2,
    "High": 3
}

def evaluate_alert_threshold(findings, threshold="Medium"):
    """
    Tuần 5: Đối chiếu mức độ phát hiện (severity) với ngưỡng cảnh báo (threshold).
    Trả về danh sách các phát hiện đủ điều kiện kích hoạt Alert.
    """
    min_rank = SEVERITY_LEVELS.get(threshold, 2)
    triggered_alerts = []
    for item in findings:
        rank = SEVERITY_LEVELS.get(item.get("severity"), 0)
        if rank >= min_rank:
            alert_item = dict(item)
            alert_item["trigger_alert"] = True
            alert_item["threshold_applied"] = threshold
            triggered_alerts.append(alert_item)
    return triggered_alerts


class TestWeek5Verification(unittest.TestCase):
    def test_1_pass_case_fully_configured(self):
        """Ca đạt: Trang HTML cấu hình đầy đủ CSP, XCTO và HttpOnly."""
        secure_response = {
            "url": "http://127.0.0.1:5000/secure-home",
            "status": "completed",
            "headers": {
                "Content-Type": "text/html; charset=utf-8",
                "Content-Security-Policy": "default-src 'self'",
                "X-Content-Type-Options": "nosniff",
                "Set-Cookie": "session_id=abc123secret; Path=/; HttpOnly; SameSite=Lax"
            }
        }
        findings = analyze_response(secure_response)
        self.assertEqual(len(findings), 0, "Trang cấu hình đúng không được sinh ra phát hiện lỗi.")

    def test_2_fail_case_missing_configurations(self):
        """Ca thiếu cấu hình: Thiếu cả 3 thiết lập bảo mật."""
        insecure_response = {
            "url": "http://127.0.0.1:5000/insecure-login",
            "status": "completed",
            "headers": {
                "Content-Type": "text/html",
                "Set-Cookie": "session_id=xyz987secret; Path=/"
            }
        }
        findings = analyze_response(insecure_response)
        self.assertEqual(len(findings), 3)
        severities = {f["rule_id"]: f["severity"] for f in findings}
        self.assertEqual(severities["SEC-HDR-CSP"], "Medium")
        self.assertEqual(severities["SEC-HDR-XCTO"], "Low")
        self.assertEqual(severities["SEC-CKI-HTTPONLY"], "High")

    def test_3_not_applicable_cases(self):
        """Ca quy tắc không áp dụng: API JSON, cookie không phải phiên, và tắt qua config."""
        # 3a. API JSON + cookie thường (không phải session cookie)
        api_response = {
            "url": "http://127.0.0.1:5000/api/v1/status",
            "status": "completed",
            "headers": {
                "Content-Type": "application/json",
                "X-Content-Type-Options": "nosniff",
                "Set-Cookie": "theme_mode=dark; Path=/"
            }
        }
        findings_api = analyze_response(api_response)
        self.assertEqual(len(findings_api), 0, "CSP không áp dụng cho JSON và HttpOnly không áp dụng cho cookie thường.")

        # 3b. Tắt toàn bộ quy tắc thông qua cấu hình
        raw_html = {"headers": {"Content-Type": "text/html"}}
        disabled_cfg = {"SEC-HDR-CSP": False, "SEC-HDR-XCTO": False, "SEC-CKI-HTTPONLY": False}
        self.assertEqual(len(analyze_response(raw_html, config=disabled_cfg)), 0)

    def test_4_severity_vs_alert_threshold(self):
        """Đối chiếu mức độ phát hiện với ngưỡng cảnh báo (Medium & High)."""
        insecure_response = {
            "headers": {
                "Content-Type": "text/html",
                "Set-Cookie": "session_id=token_val; Path=/"
            }
        }
        findings = analyze_response(insecure_response)

        # Ngưỡng Medium: Chỉ High (HttpOnly) và Medium (CSP) tạo cảnh báo; Low (XCTO) không tạo cảnh báo
        alerts_medium = evaluate_alert_threshold(findings, threshold="Medium")
        alert_ids_med = [a["rule_id"] for a in alerts_medium]
        self.assertEqual(alert_ids_med, ["SEC-HDR-CSP", "SEC-CKI-HTTPONLY"])

        # Ngưỡng High: Chỉ High (HttpOnly) tạo cảnh báo
        alerts_high = evaluate_alert_threshold(findings, threshold="High")
        alert_ids_high = [a["rule_id"] for a in alerts_high]
        self.assertEqual(alert_ids_high, ["SEC-CKI-HTTPONLY"])


if __name__ == "__main__":
    unittest.main(verbosity=2)