
import argparse
from pathlib import Path

from storage.db import create_scan_job, init_db
from Web_demo.config import DEMO_ORIGIN, DEMO_TARGETS


DB_PATH = Path(__file__).with_name("security_monitoring.db")



def scan_and_analyze(targets, allowed_hosts):
    # Keep this module importable by callers that only need the demo targets.
    # Scanner and worker dependencies are needed only when a scan starts.
    from worker import process_one_job

    init_db(DB_PATH)
    scan_id = create_scan_job(DB_PATH, targets, allowed_hosts)
    return process_one_job(scan_id, db_path=DB_PATH)


def main():
    parser = argparse.ArgumentParser(
        description="Automated Web Security Scanner"
    )

    parser.add_argument(
        "--url",
        help="URL website được phép kiểm tra"
    )

    parser.add_argument(
        "--enqueue",
        action="store_true",
        help="Đưa lượt quét vào hàng đợi cho Worker"
    )

    args = parser.parse_args()

    if args.url:
        from scanner.scope import normalize_host

        if normalize_host(args.url) is None:
            parser.error(
                "URL không hợp lệ. Hãy nhập URL HTTP hoặc HTTPS đầy đủ."
            )

        targets = [args.url]
        allowed_hosts = [args.url]

    else:
        targets = DEMO_TARGETS
        allowed_hosts = [DEMO_ORIGIN]

    init_db(DB_PATH)

    if args.enqueue:
        scan_id = create_scan_job(
            DB_PATH,
            targets,
            allowed_hosts
        )
        print("Đã tạo yêu cầu quét:", scan_id)
        return 0

    report = scan_and_analyze(targets, allowed_hosts)

    if report is None:
        return 1

    print("Mã lượt quét:", report["scan_id"])
    print("Trạng thái:", report["status"])

    return int(report["status"] == "failed")


if __name__ == "__main__":
    raise SystemExit(main())
