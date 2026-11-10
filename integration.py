import argparse
from pathlib import Path

from storage.db import create_scan_job, init_db
from worker import process_one_job


DB_PATH = Path(__file__).with_name("security_monitoring.db")
DEMO_ORIGIN = "http://127.0.0.1:5000"
DEMO_TARGETS = [
    f"{DEMO_ORIGIN}/secure",
    f"{DEMO_ORIGIN}/vuln-headers",
    f"{DEMO_ORIGIN}/vuln-cookie",
]


def scan_and_analyze(targets, allowed_hosts):
    init_db(DB_PATH)
    scan_id = create_scan_job(DB_PATH, targets, allowed_hosts)
    return process_one_job(scan_id, db_path=DB_PATH)


def main():
    parser = argparse.ArgumentParser(description="Chạy lượt quét web demo cục bộ.")
    parser.add_argument("--enqueue", action="store_true", help="Đưa lượt quét vào hàng đợi cho worker.")
    args = parser.parse_args()

    if args.enqueue:
        init_db(DB_PATH)
        scan_id = create_scan_job(DB_PATH, DEMO_TARGETS, [DEMO_ORIGIN])
        print("Đã tạo yêu cầu quét:", scan_id)
        return 0

    report = scan_and_analyze(DEMO_TARGETS, [DEMO_ORIGIN])
    if report is None:
        return 1
    print("Mã lượt quét:", report["scan_id"])
    return int(report["status"] == "failed")


if __name__ == "__main__":
    raise SystemExit(main())
