import sys
import sqlite3
from pathlib import Path

# Thêm thư mục gốc dự án vào sys.path để import được integration và reporter
ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR))

from integration import scan_and_analyze, DB_PATH, DEMO_ORIGIN
from reporter.sqlite_exporter import SQLiteReportExporter


def test_week3_full_pipeline():
    print("=== [TUẦN 3] KIỂM THỬ LUỒNG QUÉT -> SQLITE -> CẢNH BÁO -> BÁO CÁO ===")

    # 1. Quét 3 endpoint cơ bản của Web Demo
    targets = [
        f"{DEMO_ORIGIN}/secure",
        f"{DEMO_ORIGIN}/vuln-headers",
        f"{DEMO_ORIGIN}/vuln-cookie",
    ]
    report = scan_and_analyze(targets, [DEMO_ORIGIN])
    assert report is not None, "Lỗi: Không chạy được lượt quét!"

    scan_id = report["scan_id"]
    print(f"[1/4] Đã hoàn tất lượt quét: {scan_id} (Trạng thái: {report['status']})")

    # 2. Kiểm tra dữ liệu đã được ghi vào bảng findings và alerts trong SQLite
    conn = sqlite3.connect(DB_PATH)
    findings_count = conn.execute(
        "SELECT COUNT(*) FROM findings WHERE scan_id = ?", (scan_id,)
    ).fetchone()[0]
    alerts_count = conn.execute(
        "SELECT COUNT(*) FROM alerts WHERE scan_id = ?", (scan_id,)
    ).fetchone()[0]
    conn.close()

    print(f"[2/4] Dữ liệu SQLite -> Số phát hiện (findings): {findings_count} | Số cảnh báo (alerts): {alerts_count}")
    assert findings_count > 0, "Lỗi: Không có phát hiện nào được ghi vào SQLite!"

    # 3. Xuất báo cáo CSV và HTML trực tiếp từ SQLite
    exporter = SQLiteReportExporter(db_path=DB_PATH)
    csv_file = exporter.export_csv(scan_id=scan_id)
    html_file = exporter.export_html(scan_id=scan_id)

    assert Path(csv_file).exists() and Path(csv_file).stat().st_size > 0, "Lỗi xuất file CSV!"
    assert Path(html_file).exists() and Path(html_file).stat().st_size > 0, "Lỗi xuất file HTML!"

    print(f"[3/4] Xuất CSV thành công:  {csv_file}")
    print(f"[4/4] Xuất HTML thành công: {html_file}")
    print("=== HOÀN TẤT KIỂM THỬ TUẦN 3 ===")


if __name__ == "__main__":
    test_week3_full_pipeline()