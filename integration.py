
from scanner import run_scan
from detection_rules.rules import analyze_response
from storage.db import (
    init_db,
    save_scan_report,
    record_finding_and_alert
)

DB_PATH = "security_monitoring.db"


def scan_and_analyze(targets, allowed_hosts):
    # 1. Khởi tạo database
    init_db(DB_PATH)

    # 2. Quét website
    report = run_scan(
        targets=targets,
        allowed_hosts=allowed_hosts
    )

    # 3. Lưu báo cáo
    save_scan_report(DB_PATH, report)

    # 4. Phân tích từng response
    for response in report["results"]:
        if response["status"] != "completed":
            continue

        findings = analyze_response(response)

        # 5. Lưu findings và tạo alerts
        for finding in findings:
            record_finding_and_alert(
                db_path=DB_PATH,
                scan_id=report["scan_id"],
                url=response["url"],
                rule_id=finding["rule_id"],
                severity=finding["severity"],
                evidence=finding["evidence"]
            )

    return report


if __name__ == "__main__":
    report = scan_and_analyze(
        targets=["https://example.com"],
        allowed_hosts=["example.com"]
    )

    print("Scan ID:", report["scan_id"])
    print("Summary:", report["summary"])

    print("\nFindings:")
    for response in report["results"]:
        print("URL:", response["url"])
