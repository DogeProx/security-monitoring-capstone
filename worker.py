import time
from scanner import run_scan
from detection_rules.rules import analyze_response

from storage.db import (
    init_db,
    create_scan_job,
    get_pending_scan_job,
    update_scan_status,
    update_scan_progress,
    save_scan_report,
    record_finding_and_alert,
    recover_stuck_jobs
)

DB_PATH = "security_monitoring.db"


def process_one_job():
    """Lấy và xử lý một yêu cầu quét từ hàng đợi."""

    init_db(DB_PATH)

    # 1. Lấy job đang chờ
    job = get_pending_scan_job(DB_PATH)

    if not job:
        print("No pending scan job.")
        return None

    scan_id = job["scan_id"]

    print("Processing scan:", scan_id)

    # 2. Callback cập nhật tiến độ
    def progress_callback(completed, total, result):
        update_scan_progress(
            DB_PATH,
            scan_id,
            completed,
            total
        )

        print(
            f"Progress: {completed}/{total} - "
            f"{result['url']} - {result['status']}"
        )

    try:
        # 3. Chạy Web Scanner
        report = run_scan(
            targets=job["targets"],
            allowed_hosts=job["allowed_hosts"],
            scan_id=scan_id,
            progress_callback=progress_callback
        )

        # 4. Lưu báo cáo quét
        save_scan_report(DB_PATH, report)

        # 5. Phân tích và lưu findings
        for response in report["results"]:

            if response["status"] != "completed":
                continue

            findings = analyze_response(response)

            for finding in findings:
                record_finding_and_alert(
                    db_path=DB_PATH,
                    scan_id=scan_id,
                    url=response["url"],
                    rule_id=finding["rule_id"],
                    severity=finding["severity"],
                    evidence=finding["evidence"]
                )

        # 6. Cập nhật trạng thái job
        update_scan_status(
            DB_PATH,
            scan_id,
            report["status"].upper()
        )

        print("Scan finished:", report["status"])
        print("Summary:", report["summary"])

        return report

    except Exception as error:
        update_scan_status(
            DB_PATH,
            scan_id,
            "FAILED",
            str(error)
        )

        print("Worker error:", error)
        return None


def run_worker():
    """Chạy Worker liên tục và khôi phục job bị bỏ dở."""

    init_db(DB_PATH)

    recovered = recover_stuck_jobs(DB_PATH)

    print("Worker started.")
    print(f"Recovered jobs: {recovered}")

    try:
        while True:
            result = process_one_job()

            if result is None:
                time.sleep(3)

    except KeyboardInterrupt:
        print("\nWorker stopped by user.")


if __name__ == "__main__":
    run_worker()
