
import sqlite3
import json
from uuid import uuid4
from datetime import datetime, timezone


SEVERITY_MAP = {
    "INFO": 0,
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4
}


def get_connection(db_path: str):
    """Mở kết nối tới SQLite và bật chế độ khóa ngoại."""
    conn = sqlite3.connect(db_path, timeout=15.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")
    conn.execute("PRAGMA journal_mode = WAL;")
    return conn


def init_db(db_path: str):
    """Khởi tạo các bảng trong cơ sở dữ liệu."""
    with get_connection(db_path) as conn:
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
        """)


def save_scan_report(db_path: str, report: dict):
    """Lưu báo cáo tổng quan của lượt quét."""
    with get_connection(db_path) as conn:
        conn.execute("""
            INSERT OR IGNORE INTO scans (
                scan_id, started_at, finished_at, status
            )
            VALUES (?, ?, ?, ?)
        """, (
            report.get("scan_id"),
            report.get("started_at"),
            report.get("finished_at"),
            report.get("status")
        ))

        for res in report.get("results", []):
            conn.execute("""
                INSERT INTO results (scan_id, url, status_code)
                VALUES (?, ?, ?)
            """, (
                report.get("scan_id"),
                res.get("url"),
                res.get("status_code")
            ))


def record_finding_and_alert(
    db_path: str,
    scan_id: str,
    url: str,
    rule_id: str,
    severity: str,
    evidence: str,
    alert_threshold: str = "HIGH"
):
    """Lưu phát hiện và tự động tạo cảnh báo nếu vượt ngưỡng."""

    now = datetime.now(timezone.utc).isoformat()
    severity = severity.upper()
    alert_threshold = alert_threshold.upper()

    with get_connection(db_path) as conn:
        conn.execute("""
            INSERT OR IGNORE INTO findings (
                scan_id, url, rule_id, severity, evidence, created_at
            )
            VALUES (?, ?, ?, ?, ?, ?)
        """, (
            scan_id, url, rule_id, severity, evidence, now
        ))

        row = conn.execute("""
            SELECT finding_id
            FROM findings
            WHERE scan_id = ? AND url = ? AND rule_id = ?
        """, (scan_id, url, rule_id)).fetchone()

        if not row:
            return None

        finding_id = row["finding_id"]

        if SEVERITY_MAP.get(severity, 0) >= SEVERITY_MAP.get(
            alert_threshold, 3
        ):
            cur = conn.execute("""
                INSERT OR IGNORE INTO alerts (
                    scan_id, finding_id, severity, status, updated_at
                )
                VALUES (?, ?, ?, 'NEW', ?)
            """, (scan_id, finding_id, severity, now))

            if cur.rowcount > 0:
                alert_id = cur.lastrowid

                conn.execute("""
                    INSERT INTO audit_logs (
                        alert_id, action, timestamp_utc
                    )
                    VALUES (?, ?, ?)
                """, (
                    alert_id,
                    "Hệ thống tự động tạo cảnh báo do vượt ngưỡng",
                    now
                ))

        return finding_id


def create_scan_job(db_path, targets, allowed_hosts):
    """Tạo một yêu cầu quét mới."""

    scan_id = str(uuid4())
    now = datetime.now(timezone.utc).isoformat()

    with get_connection(db_path) as conn:
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


def get_pending_scan_job(db_path):
    """Lấy yêu cầu đang chờ và chuyển sang RUNNING."""

    now = datetime.now(timezone.utc).isoformat()

    with get_connection(db_path) as conn:
        conn.execute("BEGIN IMMEDIATE")

        job = conn.execute("""
            SELECT *
            FROM scan_jobs
            WHERE status = 'PENDING'
            ORDER BY created_at ASC
            LIMIT 1
        """).fetchone()

        if not job:
            return None

        conn.execute("""
            UPDATE scan_jobs
            SET status = 'RUNNING',
                started_at = ?
            WHERE scan_id = ?
              AND status = 'PENDING'
        """, (now, job["scan_id"]))

        return {
            "scan_id": job["scan_id"],
            "targets": json.loads(job["targets"]),
            "allowed_hosts": json.loads(job["allowed_hosts"]),
            "total": job["total"]
        }


def update_scan_status(db_path, scan_id, status, error=None):
    """Cập nhật trạng thái yêu cầu quét."""

    now = datetime.now(timezone.utc).isoformat()

    with get_connection(db_path) as conn:
        if status in ("COMPLETED", "FAILED", "PARTIAL"):
            conn.execute("""
                UPDATE scan_jobs
                SET status = ?,
                    error = ?,
                    finished_at = ?
                WHERE scan_id = ?
            """, (status, error, now, scan_id))
        else:
            conn.execute("""
                UPDATE scan_jobs
                SET status = ?,
                    error = ?
                WHERE scan_id = ?
            """, (status, error, scan_id))


def update_scan_progress(db_path, scan_id, completed, total):
    """Cập nhật tiến độ quét."""

    with get_connection(db_path) as conn:
        conn.execute("""
            UPDATE scan_jobs
            SET completed = ?,
                total = ?
            WHERE scan_id = ?
        """, (completed, total, scan_id))

def recover_stuck_jobs(db_path):
    """Đưa các job RUNNING bị bỏ dở về PENDING khi khởi động lại Worker."""

    with get_connection(db_path) as conn:
        cur = conn.execute("""
            UPDATE scan_jobs
            SET status = 'PENDING',
                started_at = NULL,
                error = 'Job được khôi phục sau khi Worker khởi động lại'
            WHERE status = 'RUNNING'
        """)

        return cur.rowcount
