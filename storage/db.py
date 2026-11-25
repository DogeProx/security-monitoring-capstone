from __future__ import annotations

from contextlib import closing
import sqlite3
import json
from uuid import uuid4
from datetime import datetime, timezone, timedelta


SEVERITY_MAP = {
    "INFO": 0,
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4
}


def get_connection(db_path: str):
    """Mở kết nối SQLite và bật chế độ khóa ngoại."""

    conn = sqlite3.connect(db_path, timeout=15.0)
    conn.row_factory = sqlite3.Row

    try:
        conn.execute("PRAGMA foreign_keys = ON;")
        conn.execute("PRAGMA journal_mode = WAL;")
    except sqlite3.Error:
        conn.close()
        raise

    return conn


def init_db(db_path: str):
    """Khởi tạo các bảng trong cơ sở dữ liệu."""

    with closing(get_connection(db_path)) as conn, conn:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS scans (
                scan_id TEXT PRIMARY KEY,
                started_at TEXT NOT NULL,
                finished_at TEXT,
                status TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS results (
                result_id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id TEXT NOT NULL,
                url TEXT NOT NULL,
                status_code INTEGER,
                FOREIGN KEY (scan_id) REFERENCES scans(scan_id)
                    ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS findings (
                finding_id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id TEXT NOT NULL,
                url TEXT NOT NULL,
                rule_id TEXT NOT NULL,
                severity TEXT NOT NULL,
                evidence TEXT,
                recommendation TEXT,
                created_at TEXT NOT NULL,
                FOREIGN KEY (scan_id) REFERENCES scans(scan_id)
                    ON DELETE CASCADE,
                UNIQUE (scan_id, url, rule_id)
            );

            CREATE TABLE IF NOT EXISTS alerts (
                alert_id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id TEXT NOT NULL,
                finding_id INTEGER NOT NULL UNIQUE,
                severity TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'NEW',
                updated_at TEXT NOT NULL,
                FOREIGN KEY (scan_id) REFERENCES scans(scan_id)
                    ON DELETE CASCADE,
                FOREIGN KEY (finding_id) REFERENCES findings(finding_id)
                    ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS audit_logs (
                log_id INTEGER PRIMARY KEY AUTOINCREMENT,
                alert_id INTEGER NOT NULL,
                action TEXT NOT NULL,
                timestamp_utc TEXT NOT NULL,
                FOREIGN KEY (alert_id) REFERENCES alerts(alert_id)
                    ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS scan_jobs (
                scan_id TEXT PRIMARY KEY,
                targets TEXT NOT NULL,
                allowed_hosts TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'PENDING',
                total INTEGER NOT NULL DEFAULT 0,
                completed INTEGER NOT NULL DEFAULT 0,
                error TEXT,
                created_at TEXT NOT NULL,
                started_at TEXT,
                finished_at TEXT
            );

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
                UNIQUE (schedule_id, scheduled_for),
                FOREIGN KEY (schedule_id)
                    REFERENCES scheduled_scans(schedule_id)
                    ON DELETE CASCADE
            );
        """)

        # The schema script may commit before this migration. Acquire a write
        # lock so concurrent startup cannot run the ALTER twice.
        conn.execute("BEGIN IMMEDIATE")

        columns = {
            row["name"]
            for row in conn.execute(
                "PRAGMA table_info(findings)"
            )
        }

        if "recommendation" not in columns:
            conn.execute(
                "ALTER TABLE findings ADD COLUMN recommendation TEXT"
            )


def save_scan_report(db_path: str, report: dict):
    """Lưu báo cáo tổng quan của lượt quét."""

    with closing(get_connection(db_path)) as conn, conn:
        conn.execute("""
            INSERT INTO scans (
                scan_id,
                started_at,
                finished_at,
                status
            )
            VALUES (?, ?, ?, ?)
            ON CONFLICT(scan_id) DO UPDATE SET
                started_at = excluded.started_at,
                finished_at = excluded.finished_at,
                status = excluded.status
        """, (
            report.get("scan_id"),
            report.get("started_at"),
            report.get("finished_at"),
            report.get("status")
        ))

        scan_id = report["scan_id"]

        conn.execute(
            "DELETE FROM results WHERE scan_id = ?",
            (scan_id,)
        )

        conn.executemany(
            """
            INSERT INTO results (
                scan_id,
                url,
                status_code
            )
            VALUES (?, ?, ?)
            """,
            [
                (
                    scan_id,
                    result.get("url"),
                    result.get("status_code")
                )
                for result in report.get("results", [])
            ]
        )


def record_finding_and_alert(
    db_path: str,
    scan_id: str,
    url: str,
    rule_id: str,
    severity: str,
    evidence: str,
    alert_threshold: str = "HIGH",
    recommendation: str | None = None,
):
    """Lưu Finding và tự động tạo Alert nếu vượt ngưỡng."""

    now = datetime.now(timezone.utc).isoformat()

    severity = severity.upper()
    alert_threshold = alert_threshold.upper()

    with closing(get_connection(db_path)) as conn, conn:
        conn.execute("""
            INSERT INTO findings (
                scan_id,
                url,
                rule_id,
                severity,
                evidence,
                recommendation,
                created_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(scan_id, url, rule_id) DO UPDATE SET
                recommendation = COALESCE(
                    findings.recommendation,
                    excluded.recommendation
                )
        """, (
            scan_id,
            url,
            rule_id,
            severity,
            evidence,
            recommendation,
            now
        ))

        row = conn.execute("""
            SELECT finding_id, severity
            FROM findings
            WHERE scan_id = ?
              AND url = ?
              AND rule_id = ?
        """, (
            scan_id,
            url,
            rule_id
        )).fetchone()

        if not row:
            return None

        finding_id = row["finding_id"]
        severity = row["severity"]

        if SEVERITY_MAP.get(severity, 0) >= SEVERITY_MAP.get(
            alert_threshold, 3
        ):
            cur = conn.execute("""
                INSERT OR IGNORE INTO alerts (
                    scan_id,
                    finding_id,
                    severity,
                    status,
                    updated_at
                )
                VALUES (?, ?, ?, 'NEW', ?)
            """, (
                scan_id,
                finding_id,
                severity,
                now
            ))

            if cur.rowcount > 0:
                alert_id = cur.lastrowid

                conn.execute("""
                    INSERT INTO audit_logs (
                        alert_id,
                        action,
                        timestamp_utc
                    )
                    VALUES (?, ?, ?)
                """, (
                    alert_id,
                    "Hệ thống tự động tạo cảnh báo do vượt ngưỡng",
                    now
                ))

        return finding_id


def transition_alert(db_path, alert_id, next_status):
    """Cập nhật trạng thái Alert và ghi lịch sử trong cùng transaction."""

    transitions = {
        "ACKNOWLEDGED": (
            ("NEW",),
            "Đã xác nhận xem cảnh báo"
        ),
        "RESOLVED": (
            ("NEW", "ACKNOWLEDGED"),
            "Đã xử lý cảnh báo"
        ),
    }

    if next_status not in transitions:
        raise ValueError(
            f"Trạng thái không hợp lệ: {next_status}"
        )

    allowed, action = transitions[next_status]
    placeholders = ", ".join("?" for _ in allowed)
    now = datetime.now(timezone.utc).isoformat()

    with closing(get_connection(db_path)) as conn, conn:
        changed = conn.execute(
            f"""
            UPDATE alerts
            SET status = ?,
                updated_at = ?
            WHERE alert_id = ?
              AND status IN ({placeholders})
            """,
            (
                next_status,
                now,
                alert_id,
                *allowed
            )
        )

        if changed.rowcount == 0:
            return False

        conn.execute("""
            INSERT INTO audit_logs (
                alert_id,
                action,
                timestamp_utc
            )
            VALUES (?, ?, ?)
        """, (
            alert_id,
            action,
            now
        ))
        return True


def create_scan_job(db_path, targets, allowed_hosts):
    """Tạo một yêu cầu quét mới."""

    scan_id = str(uuid4())
    now = datetime.now(timezone.utc).isoformat()

    with closing(get_connection(db_path)) as conn, conn:
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
            now
        ))

    return scan_id


def get_pending_scan_job(db_path, scan_id=None):
    """Lấy Job đang chờ và chuyển sang RUNNING."""

    now = datetime.now(timezone.utc).isoformat()

    with closing(get_connection(db_path)) as conn, conn:
        conn.execute("BEGIN IMMEDIATE")

        job = conn.execute("""
            SELECT *
            FROM scan_jobs
            WHERE status = 'PENDING'
              AND (? IS NULL OR scan_id = ?)
            ORDER BY created_at ASC
            LIMIT 1
        """, (
            scan_id,
            scan_id
        )).fetchone()

        if not job:
            return None

        conn.execute("""
            UPDATE scan_jobs
            SET status = 'RUNNING',
                started_at = ?
            WHERE scan_id = ?
              AND status = 'PENDING'
        """, (
            now,
            job["scan_id"]
        ))

        return {
            "scan_id": job["scan_id"],
            "targets": json.loads(job["targets"]),
            "allowed_hosts": json.loads(job["allowed_hosts"]),
            "total": job["total"]
        }


def update_scan_status(
    db_path,
    scan_id,
    status,
    error=None
):
    """Cập nhật trạng thái yêu cầu quét."""

    now = datetime.now(timezone.utc).isoformat()

    with closing(get_connection(db_path)) as conn, conn:
        if status in ("COMPLETED", "FAILED", "PARTIAL"):
            conn.execute("""
                UPDATE scan_jobs
                SET status = ?,
                    error = ?,
                    finished_at = ?
                WHERE scan_id = ?
            """, (
                status,
                error,
                now,
                scan_id
            ))
        else:
            conn.execute("""
                UPDATE scan_jobs
                SET status = ?,
                    error = ?
                WHERE scan_id = ?
            """, (
                status,
                error,
                scan_id
            ))


def update_scan_progress(
    db_path,
    scan_id,
    completed,
    total
):
    """Cập nhật tiến độ quét."""

    with closing(get_connection(db_path)) as conn, conn:
        conn.execute("""
            UPDATE scan_jobs
            SET completed = ?,
                total = ?
            WHERE scan_id = ?
        """, (
            completed,
            total,
            scan_id
        ))


def recover_stuck_jobs(db_path):
    """Đưa các Job RUNNING bị bỏ dở về PENDING."""

    with closing(get_connection(db_path)) as conn, conn:
        cur = conn.execute("""
            UPDATE scan_jobs
            SET status = 'PENDING',
                started_at = NULL,
                completed = 0,
                error = 'Job được khôi phục sau khi Worker khởi động lại'
            WHERE status = 'RUNNING'
        """)

        return cur.rowcount


# ============================================================
# SCHEDULED SCAN
# ============================================================

def create_scheduled_scan(
    db_path,
    name,
    targets,
    allowed_hosts,
    interval_seconds
):
    """Tạo một lịch quét định kỳ."""

    if interval_seconds <= 0:
        raise ValueError(
            "Chu kỳ quét phải lớn hơn 0 giây."
        )

    if not targets:
        raise ValueError(
            "Phải có ít nhất một URL mục tiêu."
        )

    now = datetime.now(timezone.utc)
    next_run = now + timedelta(seconds=interval_seconds)
    schedule_id = str(uuid4())

    with closing(get_connection(db_path)) as conn, conn:
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

    return schedule_id


def create_due_scheduled_jobs(db_path, now=None):
    """
    Tạo Scan Job cho các lịch đã đến hạn.

    Chính sách A:
    - Chỉ tạo một job cho mỗi lịch đến hạn.
    - Bỏ qua toàn bộ các lần chạy đã lỡ.
    - Lần chạy tiếp theo = thời điểm hiện tại + interval.
    """

    if now is None:
        now = datetime.now(timezone.utc)

    if now.tzinfo is None:
        raise ValueError("now phải là datetime có timezone.")

    now = now.astimezone(timezone.utc)
    now_text = now.isoformat(timespec="seconds")
    created_jobs = []

    with closing(get_connection(db_path)) as conn, conn:
        # Khóa ghi để tránh hai Scheduler xử lý cùng lúc.
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

            # Đăng ký mốc lịch trước.
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
                allowed_hosts = json.loads(
                    schedule["allowed_hosts"]
                )

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

            # Bỏ qua các mốc chạy đã lỡ.
            # Bắt đầu chu kỳ mới từ thời điểm hiện tại.
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


def get_scheduled_scans(db_path):
    """Lấy danh sách các lịch quét."""

    with closing(get_connection(db_path)) as conn:
        schedules = conn.execute("""
            SELECT *
            FROM scheduled_scans
            ORDER BY created_at DESC
        """).fetchall()

        return [
            {
                "schedule_id": row["schedule_id"],
                "name": row["name"],
                "targets": json.loads(row["targets"]),
                "allowed_hosts": json.loads(row["allowed_hosts"]),
                "interval_seconds": row["interval_seconds"],
                "next_run_at": row["next_run_at"],
                "enabled": bool(row["enabled"]),
                "created_at": row["created_at"]
            }
            for row in schedules
        ]


def set_scheduled_scan_status(
    db_path,
    schedule_id,
    enabled
):
    """Bật hoặc tắt một lịch quét."""

    with closing(get_connection(db_path)) as conn, conn:
        cursor = conn.execute("""
            UPDATE scheduled_scans
            SET enabled = ?
            WHERE schedule_id = ?
        """, (
            int(bool(enabled)),
            schedule_id
        ))

        return cursor.rowcount > 0
# ============================================================
# DATA QUERIES
# ============================================================

def get_all_scans(db_path: str):
    """Lấy danh sách các lượt quét để hiển thị lên Dashboard."""
    with closing(get_connection(db_path)) as conn:
        cursor = conn.execute("SELECT * FROM scans ORDER BY started_at DESC")
        return [dict(row) for row in cursor.fetchall()]

def get_alerts_with_details(db_path: str):
    """Lấy danh sách cảnh báo kèm theo chi tiết lỗi (để vẽ bảng)."""
    with closing(get_connection(db_path)) as conn:
        query = """
            SELECT a.alert_id, a.severity, a.status, a.updated_at,
                   f.url, f.rule_id, f.evidence
            FROM alerts a
            JOIN findings f ON a.finding_id = f.finding_id
            ORDER BY a.updated_at DESC
        """
        return [dict(row) for row in conn.execute(query).fetchall()]

def get_report_data(db_path: str):
    """Lấy dữ liệu tổng hợp cho xuất báo cáo CSV/HTML."""
    with closing(get_connection(db_path)) as conn:
        query = """
            SELECT s.started_at, s.scan_id, f.url, f.rule_id, f.severity, f.evidence, a.status as alert_status
            FROM findings f
            JOIN scans s ON f.scan_id = s.scan_id
            LEFT JOIN alerts a ON f.finding_id = a.finding_id
            ORDER BY s.started_at DESC
        """
        return [dict(row) for row in conn.execute(query).fetchall()]