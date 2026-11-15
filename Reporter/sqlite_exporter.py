import sqlite3
import csv
import html
from pathlib import Path
from datetime import datetime

# Đường dẫn DB chuẩn khớp với integration.py và worker.py
DEFAULT_DB_PATH = Path(__file__).resolve().parent.parent / "security_monitoring.db"


class SQLiteReportExporter:
    def __init__(self, db_path=DEFAULT_DB_PATH, output_dir="reports"):
        self.db_path = Path(db_path)
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def fetch_findings_with_alerts(self, scan_id=None):
        """Truy vấn phát hiện (findings) kèm trạng thái cảnh báo (alerts) từ SQLite."""
        if not self.db_path.exists():
            raise FileNotFoundError(f"Không tìm thấy cơ sở dữ liệu tại: {self.db_path}")

        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        # Đoạn truy vấn kết nối bảng findings và alerts
        query = """
            SELECT 
                f.finding_id,
                f.scan_id,
                f.url,
                f.rule_id,
                f.severity,
                f.evidence,
                f.created_at,
                COALESCE(a.status, 'NO_ALERT') AS alert_status
            FROM findings f
            LEFT JOIN alerts a ON f.finding_id = a.finding_id
        """
        params = ()
        if scan_id:
            query += " WHERE f.scan_id = ?"
            params = (scan_id,)

        query += " ORDER BY f.finding_id ASC"
        cursor.execute(query, params)
        rows = [dict(row) for row in cursor.fetchall()]
        conn.close()
        return rows

    def export_csv(self, scan_id=None):
        """Xuất báo cáo định dạng CSV từ dữ liệu SQLite."""
        data = self.fetch_findings_with_alerts(scan_id)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        tag = scan_id if scan_id else "all"
        file_path = self.output_dir / f"security_report_{tag}_{timestamp}.csv"

        headers = [
            "finding_id", "scan_id", "url", "rule_id",
            "severity", "evidence", "alert_status", "created_at"
        ]

        with open(file_path, mode="w", newline="", encoding="utf-8-sig") as f:
            writer = csv.DictWriter(f, fieldnames=headers, extrasaction="ignore")
            writer.writeheader()
            writer.writerows(data)

        return str(file_path)

    def export_html(self, scan_id=None):
        """Xuất báo cáo định dạng HTML từ dữ liệu SQLite."""
        data = self.fetch_findings_with_alerts(scan_id)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        tag = scan_id if scan_id else "all"
        file_path = self.output_dir / f"security_report_{tag}_{timestamp}.html"

        rows_html = ""
        for item in data:
            rows_html += f"""
            <tr>
                <td>{item['finding_id']}</td>
                <td>{html.escape(str(item['scan_id']))}</td>
                <td>{html.escape(str(item['url']))}</td>
                <td><strong>{html.escape(str(item['rule_id']))}</strong></td>
                <td>{html.escape(str(item['severity']))}</td>
                <td><code>{html.escape(str(item['evidence'] or ''))}</code></td>
                <td>{html.escape(str(item['alert_status']))}</td>
                <td>{html.escape(str(item['created_at']))}</td>
            </tr>
            """

        html_content = f"""<!DOCTYPE html>
<html lang="vi">
<head>
    <meta charset="UTF-8">
    <title>Báo cáo Giám sát Bảo mật Web</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        table {{ border-collapse: collapse; width: 100%; }}
        th, td {{ border: 1px solid #ccc; padding: 8px; text-align: left; }}
        th {{ background-color: #2c3e50; color: white; }}
        tr:nth-child(even) {{ background-color: #f9f9f9; }}
    </style>
</head>
<body>
    <h2>Báo Cáo Kết Quả Quét Bảo Mật (Scan ID: {html.escape(str(scan_id or 'Tất cả'))})</h2>
    <p>Thời gian xuất: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | Tổng số phát hiện: {len(data)}</p>
    <table>
        <thead>
            <tr>
                <th>ID</th>
                <th>Scan ID</th>
                <th>URL</th>
                <th>Mã quy tắc</th>
                <th>Mức độ</th>
                <th>Bằng chứng</th>
                <th>Cảnh báo</th>
                <th>Thời gian</th>
            </tr>
        </thead>
        <tbody>
            {rows_html if rows_html else '<tr><td colspan="8">Không có phát hiện lỗi nào.</td></tr>'}
        </tbody>
    </table>
</body>
</html>
"""
        with open(file_path, mode="w", encoding="utf-8") as f:
            f.write(html_content)

        return str(file_path)