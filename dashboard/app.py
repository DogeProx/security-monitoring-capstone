
from collections import defaultdict
from contextlib import closing
import sqlite3
import json
from datetime import datetime, timezone
from pathlib import Path
from zoneinfo import ZoneInfo

import streamlit as st

from integration import DEMO_ORIGIN, DEMO_TARGETS
from storage.db import create_scan_job, init_db, transition_alert


DB_PATH = Path(__file__).resolve().parent.parent / "security_monitoring.db"
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

ALERT_LABELS = {
    "open": "Mới",
    "acknowledged": "Đã xem",
    "resolved": "Đã xử lý",
}


def local_time(timestamp):
    if not timestamp:
        return None

    value = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))

    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)

    return value.astimezone(LOCAL_TIME_ZONE)


def display_time(timestamp):
    if timestamp is None:
        return "—"

    converted = local_time(timestamp)

    if converted is None:
        return "—"

    return converted.strftime("%d/%m/%Y %H:%M:%S")


def show_table(rows, empty_message):
    if not rows:
        st.info(empty_message)
        return

    for index, row in enumerate(rows, start=1):
        # Chọn thông tin làm tiêu đề mỗi bản ghi
        title = (
            row.get("Mã lượt quét")
            or row.get("Mã phát hiện")
            or row.get("Mã cảnh báo")
            or f"Bản ghi {index}"
        )

        with st.expander(f"{index}. {title}"):
            for key, value in row.items():
                st.markdown(f"**{key}:** {value}")


def load_dashboard_data():
    """Đọc dữ liệu quét trực tiếp từ SQLite."""

    with closing(sqlite3.connect(DB_PATH)) as conn, conn:
        conn.row_factory = sqlite3.Row
        conn.execute("BEGIN")

        jobs = conn.execute("""
            SELECT *
            FROM scan_jobs
            ORDER BY created_at DESC
        """).fetchall()

        finding_rows = conn.execute("""
            SELECT *
            FROM findings
            ORDER BY created_at DESC
        """).fetchall()

        alert_rows = conn.execute("""
            SELECT *
            FROM alerts
            ORDER BY updated_at DESC
        """).fetchall()

        audit_rows = conn.execute("""
            SELECT alert_id, action, timestamp_utc
            FROM audit_logs
            ORDER BY timestamp_utc, log_id
        """).fetchall()

    history = defaultdict(list)
    for row in audit_rows:
        history[row["alert_id"]].append((row["timestamp_utc"], row["action"]))

    scans = []

    for job in jobs:
        targets = json.loads(job["targets"])

        status = job["status"].lower()

        if status == "pending":
            status = "queued"

        scans.append({
            "scan_id": job["scan_id"],
            "target": ", ".join(targets),
            "created_at": job["created_at"],
            "finished_at": job["finished_at"],
            "status": status,
            "total": job["total"],
            "completed": job["completed"],
            "error": job["error"]
        })

    findings = []

    for item in finding_rows:
        findings.append({
            "finding_id": item["finding_id"],
            "scan_id": item["scan_id"],
            "url": item["url"],
            "rule_id": item["rule_id"],
            "severity": item["severity"].lower(),
            "evidence": item["evidence"],
            "recommendation": (
                item["recommendation"] or "Chưa có thông tin khắc phục trong database."
            )
        })

    alerts = []

    for item in alert_rows:
        status = item["status"].lower()

        if status == "new":
            status = "open"

        alerts.append({
            "alert_id": item["alert_id"],
            "finding_id": item["finding_id"],
            "updated_at": item["updated_at"],
            "history": history[item["alert_id"]],
            "severity": item["severity"].lower(),
            "status": status
        })

    return {
        "scans": scans,
        "findings": findings,
        "alerts": alerts
    }


def show_scan_controls():
    st.subheader("Tạo lượt quét")
    choices = {"Tất cả trang demo": DEMO_TARGETS}
    choices.update({url.removeprefix(DEMO_ORIGIN): [url] for url in DEMO_TARGETS})
    selection = st.selectbox("Mục tiêu quét", list(choices), key="scan_selection")
    st.caption("Khởi động web demo và worker để xử lý lượt quét đang chờ.")
    queue_col, refresh_col = st.columns(2)
    if queue_col.button("Đưa vào hàng đợi", type="primary", key="queue_scan"):
        scan_id = create_scan_job(DB_PATH, choices[selection], [DEMO_ORIGIN])
        st.success(f"Đã tạo lượt quét {scan_id}.")
    refresh_col.button("Tải lại kết quả", key="refresh_results")


def show_alerts(alerts, findings):
    if not alerts:
        st.info("Không có cảnh báo phù hợp với bộ lọc.")
        return

    for alert in alerts:
        alert_id = alert["alert_id"]
        status = alert["status"]
        finding = findings[alert["finding_id"]]
        label = ALERT_LABELS.get(status, status)
        with st.expander(f"Cảnh báo {alert_id} · {label}"):
            st.text(f"URL: {finding['url']}")
            st.text(f"Mã phát hiện: {finding['finding_id']} · {finding['rule_id']}")
            st.text(f"Mức độ: {SEVERITY_LABELS.get(alert['severity'], alert['severity'])}")
            st.text(f"Cập nhật: {display_time(alert['updated_at'])}")
            st.text(f"Bằng chứng: {finding['evidence']}")
            st.text(f"Khắc phục: {finding['recommendation']}")

            if status == "open" and st.button("Xác nhận đã xem", key=f"ack_{alert_id}"):
                apply_alert_transition(alert_id, "ACKNOWLEDGED")
            if status in {"open", "acknowledged"} and st.button(
                "Đánh dấu đã xử lý", key=f"resolve_{alert_id}"
            ):
                apply_alert_transition(alert_id, "RESOLVED")

            st.markdown("**Lịch sử cảnh báo**")
            if not alert["history"]:
                st.caption("Chưa có mục lịch sử.")
            for timestamp, action in alert["history"]:
                st.text(f"{display_time(timestamp)} · {action}")


def apply_alert_transition(alert_id, next_status):
    try:
        transition_alert(DB_PATH, alert_id, next_status)
    except sqlite3.Error as error:
        st.error(f"Không thể cập nhật cảnh báo: {error}")
    else:
        st.rerun()


def main():
    st.set_page_config(
        page_title="Web Security Scanner Dashboard",
        layout="wide"
    )

    st.title("Web Security Scanner Dashboard")

    st.caption(
        "Dữ liệu quét trực tiếp từ SQLite · Giờ Việt Nam (UTC+7)"
    )

    # Đọc dữ liệu từ database
    try:
        init_db(DB_PATH)
        show_scan_controls()
        sample = load_dashboard_data()

    except sqlite3.Error as error:
        st.error(f"Không thể đọc database: {error}")
        st.info(
            "Hãy kiểm tra quyền đọc và ghi tệp security_monitoring.db."
        )
        return

    except (json.JSONDecodeError, TypeError) as error:
        st.error(f"Dữ liệu trong database không hợp lệ: {error}")
        return

    scans = sorted(
        sample["scans"],
        key=lambda scan: scan["created_at"] or "",
        reverse=True
    )

    if not scans:
        st.info("Chưa có lượt quét. Chọn mục tiêu demo để tạo lượt quét đầu tiên.")
        return

    # Chuẩn bị dữ liệu lọc
    scan_dates = {
        scan["scan_id"]: local_time(scan["created_at"]).date()
        for scan in scans
        if scan["created_at"]
    }

    targets = sorted({
        scan["target"] for scan in scans
    })

    first_day = min(scan_dates.values())
    last_day = max(scan_dates.values())

    # Sidebar
    st.sidebar.header("Bộ lọc")

    selected_dates = st.sidebar.date_input(
        "Khoảng ngày tạo lượt quét",
        value=(first_day, last_day),
        min_value=first_day,
        max_value=last_day,
        format="DD/MM/YYYY",
        key="date_range"
    )

    target = st.sidebar.selectbox(
        "Mục tiêu",
        [None, *targets],
        format_func=lambda value: value or "Tất cả",
        key="target"
    )

    severity = st.sidebar.selectbox(
        "Mức độ",
        [None, *SEVERITY_LABELS],
        format_func=lambda value: (
            SEVERITY_LABELS.get(value, "Tất cả")
        ),
        key="severity"
    )

    st.sidebar.caption(
        "Mức độ áp dụng cho phát hiện và cảnh báo."
    )

    if len(selected_dates) != 2:
        st.info(
            "Chọn ngày bắt đầu và ngày kết thúc để xem kết quả."
        )
        return

    start_day, end_day = selected_dates

    # Lọc lượt quét
    visible_scans = [
        scan for scan in scans
        if scan["scan_id"] in scan_dates
        and start_day <= scan_dates[scan["scan_id"]] <= end_day
        and (target is None or scan["target"] == target)
    ]

    visible_scan_ids = {
        scan["scan_id"] for scan in visible_scans
    }

    # Lọc findings
    findings = {
        item["finding_id"]: item
        for item in sample["findings"]
        if item["scan_id"] in visible_scan_ids
        and (
            severity is None
            or item["severity"] == severity
        )
    }

    # Lọc alerts
    alerts = sorted(
        (
            item for item in sample["alerts"]
            if item["finding_id"] in findings
        ),
        key=lambda alert: alert["updated_at"] or "",
        reverse=True
    )

    # Tổng quan
    st.header("Tổng quan")

    scan_col, pages_col, finding_col, alert_col = st.columns(4)

    scan_col.metric(
        "Lượt quét",
        len(visible_scans)
    )

    pages_col.metric(
        "Tổng URL yêu cầu",
        sum(scan["total"] for scan in visible_scans)
    )

    finding_col.metric(
        "Phát hiện",
        len(findings)
    )

    alert_col.metric(
        "Cảnh báo",
        len(alerts)
    )

    # Các tab
    scan_tab, finding_tab, alert_tab = st.tabs([
        "Lượt quét",
        "Phát hiện",
        "Cảnh báo"
    ])

    # Tab lượt quét
    with scan_tab:
        show_table(
            [
                {
                    "Mã lượt quét": scan["scan_id"],
                    "Mục tiêu": scan["target"],
                    "Tạo lúc": display_time(scan["created_at"]),
                    "Kết thúc": display_time(scan["finished_at"]),
                    "Trạng thái": SCAN_LABELS.get(
                        scan["status"],
                        scan["status"]
                    ),
                    "URL thành công": scan["completed"],
                    "Tổng URL": scan["total"],
                    "Thông tin lỗi": scan.get("error") or "—"
                }
                for scan in visible_scans
            ],
            "Không có lượt quét trong phạm vi đã chọn."
        )

    # Tab findings
    with finding_tab:
        show_table(
            [
                {
                    "Mã phát hiện": item["finding_id"],
                    "Mã lượt quét": item["scan_id"],
                    "URL": item["url"],
                    "Quy tắc": item["rule_id"],
                    "Mức độ": SEVERITY_LABELS.get(
                        item["severity"],
                        item["severity"]
                    ),
                    "Bằng chứng": item["evidence"],
                    "Khắc phục": item["recommendation"]
                }
                for item in findings.values()
            ],
            "Không có phát hiện phù hợp với bộ lọc."
        )

    with alert_tab:
        show_alerts(alerts, findings)


if __name__ == "__main__":
    main()
