from rules import analyze_response

def process_scan_report(scan_report, rules_config=None):
    """
    Tuần 3: Tích hợp module Rules với module Web Scanner.
    Đầu vào: scan_report (từ hàm run_scan của Thành viên 2)
    Đầu ra: Danh sách tất cả các findings kèm theo scan_id và url để gửi cho Thành viên 3 (SQLite)
    """
    all_findings = []
    
    # Duyệt qua từng URL đã được quét thành công
    for result in scan_report.get("results", []):
        if result.get("status") == "completed":
            
            # Chạy phân tích phản hồi
            findings = analyze_response(result, config=rules_config)
            
            # Bổ sung thông tin ngữ cảnh vào từng finding
            for finding in findings:
                finding["scan_id"] = result.get("scan_id")
                finding["url"] = result.get("url")
                all_findings.append(finding)
                
    return all_findings
