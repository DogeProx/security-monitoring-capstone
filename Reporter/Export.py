import argparse
from contextlib import closing
import csv
from html import escape
from pathlib import Path
import sqlite3
from urllib.parse import urlsplit

DEFAULT_REMEDIATIONS = {
    "SEC-HDR-CSP": "Thêm header Content-Security-Policy phù hợp (ví dụ: default-src 'self') cho phản hồi HTML.",
    "SEC-HDR-XCTO": "Thêm header X-Content-Type-Options: nosniff để ngăn trình duyệt tự đoán kiểu MIME.",
    "SEC-CKI-HTTPONLY": "Bổ sung cờ HttpOnly cho cookie phiên nhạy cảm để chặn truy cập từ JavaScript.",
}

ALERT_STATUS_LABELS = {
    "NEW": "Mới",
    "ACKNOWLEDGED": "Đã xem",
    "RESOLVED": "Đã xử lý",
}

mock_data = [
    {
        "Thời điểm": "2026-11-09 18:00:00", "Mục tiêu": "localhost:5000",
        "URL": "/vuln-headers", "Quy tắc": "Thiếu CSP", "Mức độ": "High",
        "Bằng chứng": "Response headers missing Content-Security-Policy",
        "Cách khắc phục": "Thêm header Content-Security-Policy", "Trạng thái cảnh báo": "Mới"
    },
    {
        "Thời điểm": "2026-11-09 18:00:01", "Mục tiêu": "localhost:5000",
        "URL": "/vuln-cookie", "Quy tắc": "Cookie thiếu HttpOnly", "Mức độ": "Medium",
        "Bằng chứng": "Set-Cookie: session_id=token456",
        "Cách khắc phục": "Thêm flag HttpOnly vào Set-Cookie", "Trạng thái cảnh báo": "Đã xem"
    }
]

REPORT_COLUMNS = tuple(mock_data[0])


def load_report(database, scan_id=None):
    if not Path(database).is_file():
        raise FileNotFoundError(f"Không tìm thấy cơ sở dữ liệu: {database}")

    query = """
        SELECT findings.*, alerts.status AS alert_status
        FROM findings
        LEFT JOIN alerts ON alerts.finding_id = findings.finding_id
    """
    params = ()
    if scan_id:
        query += " WHERE findings.scan_id = ?"
        params = (scan_id,)
    query += " ORDER BY findings.created_at DESC, findings.finding_id DESC"

    with closing(sqlite3.connect(database)) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(query, params).fetchall()

    data = []
    for row in rows:
        item = dict(row)
        raw_status = item["alert_status"] or ""
        recommendation = item.get("recommendation") or DEFAULT_REMEDIATIONS.get(item["rule_id"], "")
        data.append({
            "Thời điểm": item["created_at"],
            "Mục tiêu": urlsplit(item["url"]).netloc,
            "URL": item["url"],
            "Quy tắc": item["rule_id"],
            "Mức độ": item["severity"],
            "Bằng chứng": item["evidence"] or "",
            "Cách khắc phục": recommendation,
            "Trạng thái cảnh báo": ALERT_STATUS_LABELS.get(raw_status, raw_status),
        })
    return data


def export_csv(data, filename="report.csv"):
    keys = data[0].keys() if data else REPORT_COLUMNS
    with open(filename, "w", newline="", encoding="utf-8-sig") as f:
        writer = csv.DictWriter(f, fieldnames=keys)
        writer.writeheader()
        writer.writerows(data)


def export_html(data, filename="report.html"):
    keys = data[0].keys() if data else REPORT_COLUMNS
    headings = "".join(f"<th>{escape(str(key))}</th>" for key in keys)
    rows = []
    for row in data:
        cells = "".join(f"<td>{escape(str(row.get(key, '')))}</td>" for key in keys)
        rows.append(f"<tr>{cells}</tr>")

    with open(filename, "w", encoding="utf-8") as stream:
        stream.write(
            '<!doctype html><html lang="vi"><meta charset="utf-8">'
            f"<title>Báo cáo quét web</title><body><table><thead><tr>{headings}</tr></thead>"
            f"<tbody>{''.join(rows)}</tbody></table></body></html>"
        )


def main():
    parser = argparse.ArgumentParser(description="Xuất báo cáo quét web dưới dạng CSV và HTML.")
    parser.add_argument("--database", type=Path, help="Tệp SQLite chứa dữ liệu quét.")
    parser.add_argument("--scan-id", help="Lọc theo Scan ID cụ thể (bỏ trống để xuất tất cả).")
    args = parser.parse_args()
    try:
        data = load_report(args.database, scan_id=args.scan_id) if args.database else mock_data
        export_csv(data)
        export_html(data)
    except (OSError, sqlite3.Error) as error:
        parser.error(str(error))
    print(f"Đã xuất {len(data)} phát hiện vào report.csv và report.html.")


if __name__ == "__main__":
    main()