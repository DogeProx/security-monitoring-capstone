import sqlite3
from datetime import datetime, timezone

# Từ điển quy đổi mức độ nghiêm trọng ra điểm số để dễ so sánh ngưỡng
SEVERITY_MAP = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}

def get_connection(db_path: str):
    """Mở kết nối tới SQLite và bật chế độ khóa ngoại."""
    conn = sqlite3.connect(db_path, timeout=15.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")
    conn.execute("PRAGMA journal_mode = WAL;") # Giúp đọc/ghi đồng thời không bị lỗi
    return conn

def init_db(db_path: str):
    """Khởi tạo các kệ hàng (bảng) trong kho (cơ sở dữ liệu)."""
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
                FOREIGN KEY (scan_id) REFERENCES scans(scan_id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS findings (
                finding_id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id TEXT NOT NULL,
                url TEXT NOT NULL,
                rule_id TEXT NOT NULL,
                severity TEXT NOT NULL,
                evidence TEXT,
                created_at TEXT NOT NULL,
                FOREIGN KEY (scan_id) REFERENCES scans(scan_id) ON DELETE CASCADE,
                UNIQUE (scan_id, url, rule_id)
            );

            CREATE TABLE IF NOT EXISTS alerts (
                alert_id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id TEXT NOT NULL,
                finding_id INTEGER NOT NULL UNIQUE,
                severity TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'NEW',
                updated_at TEXT NOT NULL,
                FOREIGN KEY (scan_id) REFERENCES scans(scan_id) ON DELETE CASCADE,
                FOREIGN KEY (finding_id) REFERENCES findings(finding_id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS audit_logs (
                log_id INTEGER PRIMARY KEY AUTOINCREMENT,
                alert_id INTEGER NOT NULL,
                action TEXT NOT NULL,
                timestamp_utc TEXT NOT NULL,
                FOREIGN KEY (alert_id) REFERENCES alerts(alert_id) ON DELETE CASCADE
            );
        """)

def save_scan_report(db_path: str, report: dict):
    """Lưu báo cáo tổng quan từ Thành viên 2."""
    with get_connection(db_path) as conn:
        # Lưu lượt quét
        conn.execute(
            "INSERT OR IGNORE INTO scans (scan_id, started_at, finished_at, status) VALUES (?, ?, ?, ?)",
            (report.get("scan_id"), report.get("started_at"), report.get("finished_at"), report.get("status"))
        )
        
        # Lưu kết quả từng URL
        for res in report.get("results", []):
            conn.execute(
                "INSERT INTO results (scan_id, url, status_code) VALUES (?, ?, ?)",
                (report.get("scan_id"), res.get("url"), res.get("status_code"))
            )

def record_finding_and_alert(db_path: str, scan_id: str, url: str, rule_id: str, severity: str, evidence: str, alert_threshold: str = "HIGH"):
    """Lưu lỗi bảo mật và TỰ ĐỘNG sinh cảnh báo nếu lỗi nghiêm trọng."""
    now = datetime.now(timezone.utc).isoformat()
    severity = severity.upper()
    alert_threshold = alert_threshold.upper()

    with get_connection(db_path) as conn:
        # 1. Lưu phát hiện lỗi (bỏ qua nếu trùng lặp)
        conn.execute("""
            INSERT OR IGNORE INTO findings (scan_id, url, rule_id, severity, evidence, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (scan_id, url, rule_id, severity, evidence, now))

        # Lấy lại ID của lỗi vừa lưu
        row = conn.execute(
            "SELECT finding_id FROM findings WHERE scan_id = ? AND url = ? AND rule_id = ?",
            (scan_id, url, rule_id)
        ).fetchone()
        
        if not row:
            return None
            
        finding_id = row["finding_id"]

        # 2. Logic Hệ Thống Cảnh Báo: So sánh mức độ lỗi với ngưỡng (Mặc định là HIGH)
        if SEVERITY_MAP.get(severity, 0) >= SEVERITY_MAP.get(alert_threshold, 3):
            # Tạo cảnh báo mới
            cur = conn.execute("""
                INSERT OR IGNORE INTO alerts (scan_id, finding_id, severity, status, updated_at)
                VALUES (?, ?, ?, 'NEW', ?)
            """, (scan_id, finding_id, severity, now))
            
            # Nếu cảnh báo vừa được tạo thành công, ghi vào lịch sử (audit log)
            if cur.rowcount > 0:
                alert_id = cur.lastrowid
                conn.execute(
                    "INSERT INTO audit_logs (alert_id, action, timestamp_utc) VALUES (?, ?, ?)",
                    (alert_id, "Hệ thống tự động tạo cảnh báo do vượt ngưỡng", now)
                )

        return finding_id