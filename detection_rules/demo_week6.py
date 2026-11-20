from detection_rules.integration import process_scan_report
from detection_rules.test_rules_week5 import evaluate_alert_threshold


def run_comparison_demo():
    """
    Tuần 6: Demo so sánh trực quan giữa một trang cấu hình đúng và một trang thiếu thiết lập,
    kèm phân tích bằng chứng (evidence) và đối chiếu ngưỡng cảnh báo.
    """
    mock_scan_report = {
        "scan_id": "scan-demo-week6-001",
        "status": "completed",
        "results": [
            {
                "scan_id": "scan-demo-week6-001",
                "url": "http://127.0.0.1:5000/trang-cau-hinh-dung",
                "status": "completed",
                "status_code": 200,
                "headers": {
                    "Content-Type": "text/html; charset=utf-8",
                    "Content-Security-Policy": "default-src 'self'; script-src 'self'",
                    "X-Content-Type-Options": "nosniff",
                    "Set-Cookie": "session_id=secret_token_999; Path=/; HttpOnly; Secure"
                }
            },
            {
                "scan_id": "scan-demo-week6-001",
                "url": "http://127.0.0.1:5000/trang-thieu-thiet-lap",
                "status": "completed",
                "status_code": 200,
                "headers": {
                    "Content-Type": "text/html; charset=utf-8",
                    "Set-Cookie": "session_id=secret_token_999; Path=/"
                }
            }
        ]
    }

    alert_threshold = "Medium"
    all_findings = process_scan_report(mock_scan_report)

    print("=" * 72)
    print("DEMO SO SÁNH CẤU HÌNH BẢO MẬT HTTP RESPONSE (TUẦN 6 - THÀNH VIÊN 4)")
    print(f"Ngưỡng kích hoạt cảnh báo (Alert Threshold): >= {alert_threshold}")
    print("=" * 72)

    for page in mock_scan_report["results"]:
        url = page["url"]
        page_findings = [f for f in all_findings if f["url"] == url]
        triggered_alerts = evaluate_alert_threshold(page_findings, threshold=alert_threshold)
        alert_rule_ids = {a["rule_id"] for a in triggered_alerts}

        print(f"\n[MỤC TIÊU]: {url}")
        print("-" * 72)
        if not page_findings:
            print("-> KẾT QUẢ: ĐẠT CHUẨN (0 phát hiện lỗ hổng)")
            print("-> GIẢI THÍCH BẰNG CHỨNG:")
            print("   1. Header 'Content-Security-Policy' có mặt -> Ngăn chặn chèn mã độc XSS.")
            print("   2. Header 'X-Content-Type-Options: nosniff' hợp lệ -> Chống MIME-sniffing.")
            print("   3. Cookie 'session_id' có cờ 'HttpOnly' -> JavaScript không thể đọc trộm phiên.")
        else:
            print(f"-> KẾT QUẢ: PHÁT HIỆN {len(page_findings)} LỖ HỔNG CẤU HÌNH")
            for idx, f in enumerate(page_findings, start=1):
                is_alert = "CÓ (Tạo Alert)" if f["rule_id"] in alert_rule_ids else "KHÔNG (Chỉ ghi nhận Finding)"
                print(f"   [{idx}] Mã quy tắc : {f['rule_id']} | Mức độ: {f['severity']} | Cảnh báo: {is_alert}")
                print(f"       Bằng chứng : {f['evidence']}")
                print(f"       Khắc phục  : {f['remediation']}")
            print("-> LƯU Ý BẢO MẬT BẰNG CHỨNG: Hệ thống chỉ ghi nhận tên cookie ('session_id'),")
            print("   tuyệt đối ẩn giá trị token ('secret_token_999') để tránh lộ lọt phiên đăng nhập.")

    print("\n" + "=" * 72)


if __name__ == "__main__":
    run_comparison_demo()