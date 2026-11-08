from datetime import datetime
import json
from pathlib import Path
from zoneinfo import ZoneInfo

import streamlit as st


SAMPLE_FILE = Path(__file__).with_name("sample_data.json")
LOCAL_TIME_ZONE = ZoneInfo("Asia/Ho_Chi_Minh")
SCAN_LABELS = {
    "queued": "Đang chờ",
    "running": "Đang quét",
    "completed": "Hoàn tất",
    "partial": "Hoàn tất một phần",
    "failed": "Thất bại",
}
SEVERITY_LABELS = {
    "low": "Thấp",
    "medium": "Trung bình",
    "high": "Cao",
    "critical": "Nghiêm trọng",
}
ALERT_LABELS = {"open": "Mới", "acknowledged": "Đã xem", "resolved": "Đã xử lý"}


def local_time(timestamp):
    return datetime.fromisoformat(timestamp).astimezone(LOCAL_TIME_ZONE)


def display_time(timestamp):
    if timestamp is None:
        return "—"
    return local_time(timestamp).strftime("%d/%m/%Y %H:%M:%S")


def show_table(rows, empty_message):
    if rows:
        st.dataframe(rows, hide_index=True)
    else:
        st.info(empty_message)


def main():
    st.set_page_config(page_title="Web Security Scanner Dashboard", layout="wide")
    st.title("Web Security Scanner Dashboard")
    st.caption("Tuần 2 · Kết quả quét mô phỏng · Giờ Việt Nam (UTC+7)")

    sample = json.loads(SAMPLE_FILE.read_text(encoding="utf-8"))
    scans = sorted(sample["scans"], key=lambda scan: scan["created_at"], reverse=True)
    if not scans:
        st.info("Chưa có dữ liệu lượt quét.")
        return

    scan_dates = {
        scan["scan_id"]: local_time(scan["created_at"]).date() for scan in scans
    }
    targets = sorted({scan["target"] for scan in scans})
    first_day, last_day = min(scan_dates.values()), max(scan_dates.values())

    st.sidebar.header("Bộ lọc")
    selected_dates = st.sidebar.date_input(
        "Khoảng ngày tạo lượt quét",
        value=(first_day, last_day),
        min_value=first_day,
        max_value=last_day,
        format="DD/MM/YYYY",
        key="date_range",
    )
    target = st.sidebar.selectbox(
        "Mục tiêu",
        [None, *targets],
        format_func=lambda value: value or "Tất cả",
        key="target",
    )
    severity = st.sidebar.selectbox(
        "Mức độ",
        [None, *SEVERITY_LABELS],
        format_func=lambda value: SEVERITY_LABELS.get(value, "Tất cả"),
        key="severity",
    )
    st.sidebar.caption("Mức độ áp dụng cho phát hiện và cảnh báo.")
    if len(selected_dates) != 2:
        st.info("Chọn ngày bắt đầu và ngày kết thúc để xem kết quả.")
        st.stop()

    start_day, end_day = selected_dates
    visible_scans = [
        scan for scan in scans
        if start_day <= scan_dates[scan["scan_id"]] <= end_day
        and (target is None or scan["target"] == target)
    ]
    visible_scan_ids = {scan["scan_id"] for scan in visible_scans}
    findings = {
        item["finding_id"]: item for item in sample["findings"]
        if item["scan_id"] in visible_scan_ids
        and (severity is None or item["severity"] == severity)
    }
    alerts = sorted(
        (item for item in sample["alerts"] if item["finding_id"] in findings),
        key=lambda alert: alert["created_at"],
        reverse=True,
    )

    st.header("Tổng quan")
    scan_col, pages_col, finding_col, alert_col = st.columns(4)
    scan_col.metric("Lượt quét", len(visible_scans))
    pages_col.metric("Trang đã thử", sum(scan["pages_attempted"] for scan in visible_scans))
    finding_col.metric("Phát hiện", len(findings))
    alert_col.metric("Cảnh báo", len(alerts))

    scan_tab, finding_tab, alert_tab = st.tabs(["Lượt quét", "Phát hiện", "Cảnh báo"])
    with scan_tab:
        show_table(
            [
                {
                    "Mã lượt quét": scan["scan_id"],
                    "Mục tiêu": scan["target"],
                    "Tạo lúc": display_time(scan["created_at"]),
                    "Kết thúc": display_time(scan["finished_at"]),
                    "Trạng thái": SCAN_LABELS[scan["status"]],
                    "Trang đã thử": scan["pages_attempted"],
                    "Thông tin lỗi": scan.get("error") or "—",
                }
                for scan in visible_scans
            ],
            "Không có lượt quét trong phạm vi đã chọn.",
        )
    with finding_tab:
        show_table(
            [
                {
                    "Mã phát hiện": item["finding_id"],
                    "Mã lượt quét": item["scan_id"],
                    "URL": item["url"],
                    "Quy tắc": item["rule_id"],
                    "Mức độ": SEVERITY_LABELS[item["severity"]],
                    "Bằng chứng": item["evidence"],
                    "Khắc phục": item["recommendation"],
                }
                for item in findings.values()
            ],
            "Không có phát hiện phù hợp với bộ lọc.",
        )
    with alert_tab:
        show_table(
            [
                {
                    "Mã cảnh báo": alert["alert_id"],
                    "Thời gian": display_time(alert["created_at"]),
                    "Mã phát hiện": alert["finding_id"],
                    "URL": findings[alert["finding_id"]]["url"],
                    "Mức độ": SEVERITY_LABELS[alert["severity"]],
                    "Trạng thái": ALERT_LABELS[alert["status"]],
                }
                for alert in alerts
            ],
            "Không có cảnh báo phù hợp với bộ lọc.",
        )


if __name__ == "__main__":
    main()
