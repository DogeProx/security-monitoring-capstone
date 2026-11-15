
import argparse
import json
import time
from pathlib import Path
from uuid import uuid4
from datetime import datetime, timezone, timedelta
from contextlib import closing

from storage.db import init_db, get_connection


DB_PATH = Path(__file__).with_name("security_monitoring.db")

DEMO_ORIGIN = "http://127.0.0.1:5000"

DEMO_TARGETS = [
    f"{DEMO_ORIGIN}/secure",
    f"{DEMO_ORIGIN}/vuln-headers",
    f"{DEMO_ORIGIN}/vuln-cookie",
]


def ensure_scheduler_tables():
    """Tạo các bảng cần thiết cho Scheduled Scan."""

    init_db(DB_PATH)

    with closing(get_connection(DB_PATH)) as conn, conn:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS scheduled_scans (
                schedule_id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                targets TEXT NOT NULL,
                allowed_hosts TEXT NOT NULL,
                interval_seconds INTEGER NOT NULL,
                next_run_at TEXT NOT NULL,
                enabled INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS scheduled_scan_runs (
                run_id INTEGER PRIMARY KEY AUTOINCREMENT,
                schedule_id TEXT NOT NULL,
                scheduled_for TEXT NOT NULL,
                scan_id TEXT NOT NULL UNIQUE,
                created_at TEXT NOT NULL,
                UNIQUE(schedule_id, scheduled_for),
                FOREIGN KEY (schedule_id)
                    REFERENCES scheduled_scans(schedule_id)
            );
        """)


def add_schedule(name, targets, interval_seconds):
    """Tạo một lịch quét định kỳ."""

    if interval_seconds <= 0:
        raise ValueError("Chu kỳ quét phải lớn hơn 0 giây.")

    if not targets:
        raise ValueError("Phải có ít nhất một URL mục tiêu.")

    from scanner.scope import normalize_host
    from urllib.parse import urlsplit

    allowed_hosts = []

    for url in targets:
        if normalize_host(url) is None:
            raise ValueError(f"URL không hợp lệ: {url}")

        parsed = urlsplit(url)
        origin = f"{parsed.scheme}://{parsed.netloc}"

        if origin not in allowed_hosts:
            allowed_hosts.append(origin)

    now = datetime.now(timezone.utc)
    next_run = now + timedelta(seconds=interval_seconds)

    schedule_id = str(uuid4())

    with closing(get_connection(DB_PATH)) as conn, conn:
        conn.execute("""
            INSERT INTO scheduled_scans (
                schedule_id,
                name,
                targets,
                allowed_hosts,
                interval_seconds,
                next_run_at,
                enabled,
                created_at
            )
            VALUES (?, ?, ?, ?, ?, ?, 1, ?)
        """, (
            schedule_id,
            name,
            json.dumps(targets),
            json.dumps(allowed_hosts),
            interval_seconds,
            next_run.isoformat(timespec="seconds"),
            now.isoformat(timespec="seconds")
        ))

    print("Đã tạo lịch quét thành công.")
    print("Schedule ID:", schedule_id)
    print("Tên lịch:", name)
    print("Chu kỳ:", interval_seconds, "giây")
    print("Mục tiêu:", targets)

    return schedule_id


def create_due_scheduled_jobs():
    """
    Kiểm tra lịch đến hạn và tạo Scan Job.

    Mỗi lịch chỉ tạo một job cho mỗi mốc thời gian.
    Khi Scheduler khởi động muộn, chỉ tạo một job
    cho lần kiểm tra hiện tại, không chạy bù hàng loạt.
    """

    now = datetime.now(timezone.utc)
    now_text = now.isoformat(timespec="seconds")

    created_jobs = []

    with closing(get_connection(DB_PATH)) as conn, conn:

        # Khóa quyền ghi để tránh nhiều Scheduler xử lý
        # cùng một mốc lịch đồng thời.
        conn.execute("BEGIN IMMEDIATE")

        schedules = conn.execute("""
            SELECT *
            FROM scheduled_scans
            WHERE enabled = 1
              AND next_run_at <= ?
            ORDER BY next_run_at ASC
        """, (now_text,)).fetchall()

        for schedule in schedules:
            scheduled_for = schedule["next_run_at"]
            scan_id = str(uuid4())

            # Đăng ký mốc lịch.
            # UNIQUE(schedule_id, scheduled_for) chống trùng.
            cursor = conn.execute("""
                INSERT OR IGNORE INTO scheduled_scan_runs (
                    schedule_id,
                    scheduled_for,
                    scan_id,
                    created_at
                )
                VALUES (?, ?, ?, ?)
            """, (
                schedule["schedule_id"],
                scheduled_for,
                scan_id,
                now_text
            ))

            if cursor.rowcount > 0:
                targets = json.loads(schedule["targets"])
                allowed_hosts = json.loads(schedule["allowed_hosts"])

                # Tạo Scan Job trong cùng transaction.
                conn.execute("""
                    INSERT INTO scan_jobs (
                        scan_id,
                        targets,
                        allowed_hosts,
                        status,
                        total,
                        completed,
                        created_at
                    )
                    VALUES (?, ?, ?, 'PENDING', ?, 0, ?)
                """, (
                    scan_id,
                    json.dumps(targets),
                    json.dumps(allowed_hosts),
                    len(targets),
                    now_text
                ))

                created_jobs.append(scan_id)

                print(
                    f"[SCHEDULER] Đã tạo Scan Job: {scan_id}"
                )

            # Đặt lần chạy tiếp theo từ thời điểm hiện tại.
            # Tránh tạo hàng loạt job cho những mốc đã bỏ lỡ.
            next_run = now + timedelta(
                seconds=schedule["interval_seconds"]
            )

            conn.execute("""
                UPDATE scheduled_scans
                SET next_run_at = ?
                WHERE schedule_id = ?
            """, (
                next_run.isoformat(timespec="seconds"),
                schedule["schedule_id"]
            ))

    return created_jobs


def list_schedules():
    """Hiển thị các lịch quét đã cấu hình."""

    with closing(get_connection(DB_PATH)) as conn:
        schedules = conn.execute("""
            SELECT *
            FROM scheduled_scans
            ORDER BY created_at DESC
        """).fetchall()

    if not schedules:
        print("Chưa có lịch quét nào.")
        return

    for schedule in schedules:
        print("-" * 50)
        print("Schedule ID:", schedule["schedule_id"])
        print("Tên:", schedule["name"])
        print("Chu kỳ:", schedule["interval_seconds"], "giây")
        print("Bật:", bool(schedule["enabled"]))
        print("Lần chạy tiếp theo:", schedule["next_run_at"])
        print("Mục tiêu:", json.loads(schedule["targets"]))


def run_scheduler():
    """Chạy Scheduler liên tục."""

    ensure_scheduler_tables()

    print("Scheduler started.")
    print("Đang kiểm tra lịch quét mỗi giây.")
    print("Nhấn Ctrl+C để dừng.")

    try:
        while True:
            create_due_scheduled_jobs()
            time.sleep(1)

    except KeyboardInterrupt:
        print("\nScheduler stopped.")


def main():
    parser = argparse.ArgumentParser(
        description="Scheduled Web Security Scanner"
    )

    parser.add_argument(
        "--add-every",
        type=int,
        help="Tạo lịch quét định kỳ (đơn vị: giây)"
    )

    parser.add_argument(
        "--name",
        default="Demo scheduled scan",
        help="Tên lịch quét"
    )

    parser.add_argument(
        "--url",
        action="append",
        help="URL mục tiêu. Có thể sử dụng nhiều lần."
    )

    parser.add_argument(
        "--list",
        action="store_true",
        help="Hiển thị danh sách lịch quét"
    )

    args = parser.parse_args()

    ensure_scheduler_tables()

    if args.add_every is not None:
        targets = args.url if args.url else DEMO_TARGETS

        add_schedule(
            name=args.name,
            targets=targets,
            interval_seconds=args.add_every
        )
        return

    if args.list:
        list_schedules()
        return

    run_scheduler()


if __name__ == "__main__":
    main()
