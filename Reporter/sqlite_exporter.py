import sqlite3
import csv
import html
import argparse
from pathlib import Path
from datetime import datetime
from urllib.parse import urlsplit

DEFAULT_DB_PATH = Path(__file__).resolve().parent.parent / "security_monitoring.db"

# Hướng dẫn khắc phục mặc định theo mã quy tắc nếu bản ghi trong DB để trống
DEFAULT_REMEDIATIONS = {
    "SEC-HDR-CSP": "Thêm header Content-Security-Policy phù hợp (ví dụ: default-src 'self') cho phản hồi HTML.",
    "SEC-HDR-XCTO": "Thêm header X-Content-Type-Options: nosniff để ngăn trình duyệt tự đoán kiểu MIME.",
    "SEC-CKI-HTTPONLY": "Bổ sung cờ HttpOnly cho cookie phiên nhạy cảm để chặn truy cập từ JavaScript.",
}

ALERT_STATUS_LABELS = {
    "NEW": "Mới",
    "ACKNOWLEDGED": "Đã xem",
    "RESOLVED": "Đã xử lý",
    "NO_ALERT": "Không cảnh báo",
}


class SQLiteReportExporter:
    def __init__(self, db_path=DEFAULT_DB_PATH, output_dir="reports"):
        self.db_path = Path(db_path)
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def fetch_findings_with_alerts(self, scan_id=None):
        """Truy vấn phát hiện (findings) kèm mục tiêu quét, cách khắc phục và trạng thái cảnh báo."""
        if not self.db_path.exists():
            raise FileNotFoundError(f"Không tìm thấy cơ sở dữ liệu tại: {self.db_path}")

        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        # Kiểm tra động cấu trúc bảng findings và scans để tương thích mọi bản cập nhật DB
        finding_cols = {row[1] for row in cursor.execute("PRAGMA table_info(findings)").fetchall()}
        scan_cols = {row[1] for row in cursor.execute("PRAGMA table_info(scans)").fetchall()}

        if "remediation" in finding_cols:
            remediation_expr = "f.remediation AS remediation"
        elif "recommendation" in finding_cols:
            remediation_expr = "f.recommendation AS remediation"
        else:
            remediation_expr = "'' AS remediation"

        join_scans = ""
        if "target" in scan_cols:
            target_expr = "s.target AS target"
            join_scans = "LEFT JOIN scans s ON f.scan_id = s.scan_id"
        elif "targets" in scan_cols:
            target_expr = "s.targets AS target"
            join_scans = "LEFT JOIN scans s ON f.scan_id = s.scan_id"
        else:
            target_expr = "'' AS target"

        query = f"""
            SELECT
                f.finding_id,
                f.scan_id,
                f.created_at,
                {target_expr},
                f.url,
                f.rule_id,
                f.severity,
                f.evidence,
                {remediation_expr},
                COALESCE(a.status, 'NO_ALERT') AS alert_status
            FROM findings f
            {join_scans}
            LEFT JOIN alerts a ON f.finding_id = a.finding_id
        """
        params = ()
        if scan_id:
            query += " WHERE f.scan_id = ?"
            params = (scan_id,)

        query += " ORDER BY f.finding_id ASC"
        cursor.execute(query, params)

        rows = []
        for row in cursor.fetchall():
            item = dict(row)
            # Điền mục tiêu từ origin của URL nếu bảng scans không lưu chuỗi target đơn
            if not item.get("target") and item.get("url"):
                parsed = urlsplit(str(item["url"]))
                item["target"] = f"{parsed.scheme}://{parsed.netloc}" if parsed.netloc else item["url"]
            # Điền cách khắc phục mặc định nếu trong DB chưa có
            if not item.get("remediation"):
                item["remediation"] = DEFAULT_REMEDIATIONS.get(
                    item.get("rule_id"), "Rà soát và bổ sung cấu hình bảo mật theo khuyến nghị OWASP."
                )
            raw_status = item.get("alert_status") or "NO_ALERT"
            item["alert_status"] = ALERT_STATUS_LABELS.get(raw_status, raw_status)
            rows.append(item)

        conn.close()
        return rows

    def export_csv(self, scan_id=None):
        """Xuất báo cáo định dạng CSV từ dữ liệu SQLite."""
        data = self.fetch_findings_with_alerts(scan_id)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        tag = scan_id if scan_id else "all"
        file_path = self.output_dir / f"security_report_{tag}_{timestamp}.csv"

        headers = [
            "finding_id", "scan_id", "created_at", "target", "url",
            "rule_id", "severity", "evidence", "remediation", "alert_status"
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
                <td>{html.escape(str(item['created_at']))}</td>
                <td>{html.escape(str(item['target']))}</td>
                <td>{html.escape(str(item['url']))}</td>
                <td><strong>{html.escape(str(item['rule_id']))}</strong></td>
                <td>{html.escape(str(item['severity']))}</td>
                <td><code>{html.escape(str(item['evidence'] or ''))}</code></td>
                <td>{html.escape(str(item['remediation']))}</td>
                <td>{html.escape(str(item['alert_status']))}</td>
            </tr>
            """

        html_content = f"""<!DOCTYPE html>
<html lang="vi">
<head>
    <meta charset="UTF-8">
    <title>Báo cáo Giám sát Bảo mật Web</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        table {{ border-collapse: collapse; width: 100%; font-size: 14px; }}
        th, td {{ border: 1px solid #ccc; padding: 8px; text-align: left; vertical-align: top; }}
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
                <th>Thời gian</th>
                <th>Mục tiêu</th>
                <th>URL</th>
                <th>Mã quy tắc</th>
                <th>Mức độ</th>
                <th>Bằng chứng</th>
                <th>Cách khắc phục</th>
                <th>Cảnh báo</th>
            </tr>
        </thead>
        <tbody>
            {rows_html if rows_html else '<tr><td colspan="10">Không có phát hiện lỗi nào.</td></tr>'}
        </tbody>
    </table>
</body>
</html>
"""
        with open(file_path, mode="w", encoding="utf-8") as f:
            f.write(html_content)

        return str(file_path)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Xuất báo cáo bảo mật CSV và HTML từ SQLite.")
    parser.add_argument("--db", default=str(DEFAULT_DB_PATH), help="Đường dẫn tới tệp SQLite")
    parser.add_argument("--scan-id", default=None, help="Lọc theo Scan ID cụ thể (bỏ trống để xuất tất cả)")
    args = parser.parse_args()

    exporter = SQLiteReportExporter(db_path=args.db)
    csv_out = exporter.export_csv(scan_id=args.scan_id)
    html_out = exporter.export_html(scan_id=args.scan_id)
    print(f"Đã xuất báo cáo CSV:  {csv_out}")
    print(f"Đã xuất báo cáo HTML: {html_out}")