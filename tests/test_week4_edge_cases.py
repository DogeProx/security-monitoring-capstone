import sys
import sqlite3
from pathlib import Path

# Thêm thư mục gốc dự án vào sys.path
ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR))

from integration import scan_and_analyze, DB_PATH, DEMO_ORIGIN


def count_findings_for_url(scan_id: str, url: str) -> int:
    """Đếm số lượng phát hiện (findings) ghi nhận được cho một URL cụ thể."""
    conn = sqlite3.connect(DB_PATH)
    count = conn.execute(
        "SELECT COUNT(*) FROM findings WHERE scan_id = ? AND url = ?",
        (scan_id, url),
    ).fetchone()[0]
    conn.close()
    return count


def test_week4_edge_cases():
    print("=== [TUẦN 4] KIỂM THỬ TÌNH HUỐNG BIÊN & BỘ DỮ LIỆU DEMO ===")

    # Nhóm 1: Kiểm thử các trang sạch, chống báo sai và trang nhiều lỗ hổng
    edge_targets = [
        f"{DEMO_ORIGIN}/secure",       # Trang sạch chuẩn
        f"{DEMO_ORIGIN}/api/data",     # API JSON (không được báo sai thiếu CSP)
        f"{DEMO_ORIGIN}/public-page",  # Trang không đặt cookie (không được báo lỗi cookie)
        f"{DEMO_ORIGIN}/vuln-multi",   # Trang chứa nhiều lỗ hổng cùng lúc
    ]

    report = scan_and_analyze(edge_targets, [DEMO_ORIGIN])
    assert report is not None, "Lỗi: Không chạy được lượt quét tình huống biên!"
    scan_id = report["scan_id"]

    c_secure = count_findings_for_url(scan_id, f"{DEMO_ORIGIN}/secure")
    c_api = count_findings_for_url(scan_id, f"{DEMO_ORIGIN}/api/data")
    c_public = count_findings_for_url(scan_id, f"{DEMO_ORIGIN}/public-page")
    c_multi = count_findings_for_url(scan_id, f"{DEMO_ORIGIN}/vuln-multi")

    print(f"[1/5] Trang sạch (/secure):          {c_secure} phát hiện (Kỳ vọng: 0)")
    print(f"[2/5] API JSON (/api/data):          {c_api} phát hiện (Kỳ vọng: 1 - Không báo sai CSP, chỉ bắt thiếu XCTO)")    
    print(f"[3/5] Không cookie (/public-page):   {c_public} phát hiện (Kỳ vọng: 0)")
    print(f"[4/5] Nhiều lỗi (/vuln-multi):       {c_multi} phát hiện (Kỳ vọng: >= 2)")

    # Nhóm 2: Thử nghiệm Web Demo không chạy (kết nối vào cổng 5999 không tồn tại)
    offline_origin = "http://127.0.0.1:5999"
    offline_report = scan_and_analyze([f"{offline_origin}/secure"], [offline_origin])
    status = offline_report["status"] if offline_report else "handled_error"
    print(f"[5/5] Ca Web Demo không chạy:        Trạng thái hệ thống = '{status}' (Không bị crash)")

    print("=== HOÀN TẤT KIỂM THỬ TUẦN 4 ===")


if __name__ == "__main__":
    test_week4_edge_cases()