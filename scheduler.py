
"""Scheduler tạo Scan Job từ các lịch quét đã đến hạn.

Chạy độc lập với Worker:
    python scheduler.py

Tạo lịch:
    python scheduler.py --add-every 300 --url https://example.com

Xem danh sách lịch:
    python scheduler.py --list
"""

import argparse
import time
from pathlib import Path
from urllib.parse import urlsplit

from scanner.scope import normalize_host
from storage.db import (
    init_db,
    create_scheduled_scan,
    create_due_scheduled_jobs,
    get_scheduled_scans,
)


DB_PATH = Path(__file__).with_name("security_monitoring.db")
POLL_INTERVAL_SECONDS = 3

DEMO_ORIGIN = "http://127.0.0.1:5000"

DEMO_TARGETS = [
    f"{DEMO_ORIGIN}/secure",
    f"{DEMO_ORIGIN}/vuln-headers",
    f"{DEMO_ORIGIN}/vuln-cookie",
]


def add_schedule(name, targets, interval_seconds):
    """Tạo một lịch quét định kỳ."""

    if interval_seconds <= 0:
        raise ValueError("Chu kỳ quét phải lớn hơn 0 giây.")

    if not targets:
        raise ValueError("Phải có ít nhất một URL mục tiêu.")

    allowed_hosts = []

    for url in targets:
        if normalize_host(url) is None:
            raise ValueError(f"URL không hợp lệ: {url}")

        parsed = urlsplit(url)
        origin = f"{parsed.scheme}://{parsed.netloc}"

        if origin not in allowed_hosts:
            allowed_hosts.append(origin)

    schedule_id = create_scheduled_scan(
        db_path=DB_PATH,
        name=name,
        targets=targets,
        allowed_hosts=allowed_hosts,
        interval_seconds=interval_seconds,
    )

    print("Đã tạo lịch quét thành công.")
    print("Schedule ID:", schedule_id)
    print("Tên lịch:", name)
    print("Chu kỳ:", interval_seconds, "giây")
    print("Mục tiêu:", targets)

    return schedule_id


def list_schedules():
    """Hiển thị danh sách lịch quét."""

    schedules = get_scheduled_scans(DB_PATH)

    if not schedules:
        print("Chưa có lịch quét nào.")
        return

    for schedule in schedules:
        print("-" * 50)
        print("Schedule ID:", schedule["schedule_id"])
        print("Tên:", schedule["name"])
        print("Chu kỳ:", schedule["interval_seconds"], "giây")
        print("Bật:", schedule["enabled"])
        print("Lần chạy tiếp theo:", schedule["next_run_at"])
        print("Mục tiêu:", schedule["targets"])


def run_scheduler(
    db_path=DB_PATH,
    poll_interval=POLL_INTERVAL_SECONDS,
):
    """Liên tục kiểm tra lịch đến hạn và tạo Scan Job."""

    if poll_interval <= 0:
        raise ValueError("poll_interval phải lớn hơn 0.")

    init_db(db_path)

    print("Scheduler started.")
    print(f"Database: {db_path}")
    print(f"Kiểm tra lịch mỗi {poll_interval} giây.")
    print("Nhấn Ctrl+C để dừng.")

    try:
        while True:
            try:
                created_jobs = create_due_scheduled_jobs(db_path)

                for scan_id in created_jobs:
                    print(f"[SCHEDULER] Đã tạo Scan Job: {scan_id}")

            except Exception as error:
                print(f"[SCHEDULER] Error: {error}")

            time.sleep(poll_interval)

    except KeyboardInterrupt:
        print("\nScheduler stopped.")


def main():
    parser = argparse.ArgumentParser(
        description="Scheduled Web Security Scanner"
    )

    parser.add_argument(
        "--add-every",
        type=int,
        help="Tạo lịch quét định kỳ, đơn vị giây",
    )

    parser.add_argument(
        "--name",
        default="Demo scheduled scan",
        help="Tên lịch quét",
    )

    parser.add_argument(
        "--url",
        action="append",
        help="URL mục tiêu. Có thể sử dụng nhiều lần.",
    )

    parser.add_argument(
        "--list",
        action="store_true",
        help="Hiển thị danh sách lịch quét",
    )

    args = parser.parse_args()

    init_db(DB_PATH)

    if args.add_every is not None:
        targets = args.url if args.url else DEMO_TARGETS

        add_schedule(
            name=args.name,
            targets=targets,
            interval_seconds=args.add_every,
        )
        return

    if args.list:
        list_schedules()
        return

    run_scheduler(DB_PATH)


if __name__ == "__main__":
    main()
