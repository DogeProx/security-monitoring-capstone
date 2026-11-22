from collections import Counter, defaultdict
from contextlib import closing
import json
import os
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit
from zoneinfo import ZoneInfo

import streamlit as st

from Web_demo.config import DEMO_ORIGIN, DEMO_TARGETS
from scanner.scope import is_in_scope, normalize_host
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

SCAN_COLORS = {
    "queued": "gray",
    "running": "blue",
    "completed": "green",
    "partial": "orange",
    "failed": "red",
}
ACTIVE_SCAN_STATUSES = {"queued", "running"}
SCAN_REFRESH_SECONDS = 2

SEVERITY_LABELS = {
    "low": "Thấp",
    "medium": "Trung bình",
    "high": "Cao",
    "critical": "Nghiêm trọng",
}
SEVERITY_RANK = {severity: rank for rank, severity in enumerate(SEVERITY_LABELS)}

RULE_TITLES = {
    "SEC-HDR-CSP": "Thiếu Content-Security-Policy",
    "SEC-HDR-XCTO": "Thiếu hoặc sai X-Content-Type-Options",
    "SEC-CKI-HTTPONLY": "Cookie thiếu HttpOnly",
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


def scan_from_row(job):
    targets = json.loads(job["targets"])
    status = job["status"].lower()
    return {
        "scan_id": job["scan_id"],
        "targets": targets,
        "target": ", ".join(targets),
        "created_at": job["created_at"],
        "started_at": job["started_at"],
        "finished_at": job["finished_at"],
        "status": "queued" if status == "pending" else status,
        "total": job["total"],
        "completed": job["completed"],
        "error": job["error"],
    }


def load_scan_history():
    with closing(sqlite3.connect(DB_PATH)) as conn:
        conn.row_factory = sqlite3.Row
        jobs = conn.execute("""
            SELECT *
            FROM scan_jobs
            ORDER BY created_at DESC, scan_id DESC
        """).fetchall()
    return [scan_from_row(job) for job in jobs]


def load_scan_report(scan_id):
    """Đọc nhất quán trạng thái, kết quả và cảnh báo của một lượt."""
    with closing(sqlite3.connect(DB_PATH)) as conn, conn:
        conn.row_factory = sqlite3.Row
        conn.execute("BEGIN")

        job = conn.execute("""
            SELECT *
            FROM scan_jobs
            WHERE scan_id = ?
        """, (scan_id,)).fetchone()
        if job is None:
            return None

        result_rows = conn.execute("""
            SELECT url, status_code
            FROM results
            WHERE scan_id = ?
        """, (scan_id,)).fetchall()

        finding_rows = conn.execute("""
            SELECT *
            FROM findings
            WHERE scan_id = ?
            ORDER BY created_at DESC
        """, (scan_id,)).fetchall()

        alert_rows = conn.execute("""
            SELECT *
            FROM alerts
            WHERE scan_id = ?
            ORDER BY updated_at DESC
        """, (scan_id,)).fetchall()

        audit_rows = conn.execute("""
            SELECT audit_logs.alert_id, audit_logs.action, audit_logs.timestamp_utc
            FROM audit_logs
            JOIN alerts ON alerts.alert_id = audit_logs.alert_id
            WHERE alerts.scan_id = ?
            ORDER BY audit_logs.timestamp_utc, audit_logs.log_id
        """, (scan_id,)).fetchall()

    history = defaultdict(list)
    for row in audit_rows:
        history[row["alert_id"]].append((row["timestamp_utc"], row["action"]))

    scan = scan_from_row(job)
    scan["responses"] = {row["url"]: row["status_code"] for row in result_rows}

    findings = {}
    for item in finding_rows:
        findings[item["finding_id"]] = {
            "finding_id": item["finding_id"],
            "url": item["url"],
            "rule_id": item["rule_id"],
            "severity": item["severity"].lower(),
            "evidence": item["evidence"],
            "recommendation": (
                item["recommendation"] or "Chưa có thông tin khắc phục trong database."
            )
        }

    alerts = []

    for item in alert_rows:
        if item["finding_id"] not in findings:
            continue
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

    return scan, findings, alerts


def read_allowed_origins():
    path = DB_PATH.with_name("dashboard_origins.txt")
    entries = os.environ.get("DASHBOARD_ALLOWED_ORIGINS", "").split(",")
    try:
        entries.extend(path.read_text(encoding="utf-8-sig").splitlines())
    except FileNotFoundError:
        pass
    except (OSError, UnicodeError):
        st.warning("Không đọc được dashboard_origins.txt. Kiểm tra quyền đọc và lưu tệp dưới dạng UTF-8.")

    origins = {DEMO_ORIGIN: None}
    for entry in entries:
        entry = entry.strip()
        if not entry or entry.startswith("#"):
            continue
        if not normalize_host(entry):
            st.warning("Bỏ qua một địa chỉ cấu hình không hợp lệ. Dùng địa chỉ bắt đầu bằng http:// hoặc https://.")
            continue
        parts = urlsplit(entry)
        origins[f"{parts.scheme}://{parts.netloc}"] = None
    return list(origins)


def show_scan_controls():
    with st.container():
        mode = st.radio("Nguồn mục tiêu", ["Trang demo", "Nhập URL"], horizontal=True)
        choices = {"Tất cả trang demo": DEMO_TARGETS}
        choices.update({url.removeprefix(DEMO_ORIGIN): [url] for url in DEMO_TARGETS})

        target_col, action_col = st.columns([4, 1], vertical_alignment="bottom")
        if mode == "Nhập URL":
            url = target_col.text_input(
                "URL cần kiểm tra",
                placeholder=DEMO_TARGETS[0],
                key="scan_url",
            ).strip()
            if url and "://" not in url:
                url = f"https://{url}"
            allowed_origins = read_allowed_origins()
            st.caption(f"Địa chỉ được phép · {', '.join(allowed_origins)}")
            with st.popover("Thêm website được phép"):
                st.write(
                    "Thêm địa chỉ gốc của website bạn quản lý hoặc được phép kiểm tra "
                    "vào dashboard_origins.txt trong thư mục dự án. "
                    "Ghi mỗi địa chỉ trên một dòng, rồi lưu và tải lại dashboard."
                )
                st.code("https://web-cua-ban.example", language=None)
        else:
            selection = target_col.selectbox("Mục tiêu demo", list(choices), key="scan_selection")

        if action_col.button("Đưa vào hàng đợi", type="primary", key="queue_scan"):
            if mode == "Nhập URL":
                if normalize_host(url) is None:
                    st.error(f"Nhập tên miền hoặc URL HTTP/HTTPS hợp lệ, ví dụ {DEMO_TARGETS[0]}")
                elif not is_in_scope(url, allowed_origins):
                    st.error(
                        "Địa chỉ vừa nhập chưa có trong phạm vi quét. "
                        "Nếu bạn được phép kiểm tra website đó, thêm địa chỉ gốc vào "
                        f"dashboard_origins.txt. Để chạy demo, nhập {DEMO_TARGETS[0]}."
                    )
                else:
                    return queue_scan([url], [url])
            else:
                return queue_scan(choices[selection], [DEMO_ORIGIN])


def queue_scan(targets, allowed_origins):
    scan_id = create_scan_job(DB_PATH, targets, allowed_origins)
    st.session_state["history_query"] = ""
    st.session_state["selected_scan"] = scan_id
    st.success("Đã tạo lượt quét.")
    return scan_id


def select_scan(scans):
    with st.expander(f"Lịch sử lượt quét · {len(scans)} lượt"):
        query = st.text_input(
            "Tìm theo URL hoặc mã lượt quét",
            key="history_query",
        ).strip().casefold()
        choices = {
            scan["scan_id"]: scan for scan in scans
            if query in scan["target"].casefold() or query in scan["scan_id"].casefold()
        }
        if choices:
            st.dataframe(
                [
                    {
                        "Mã lượt": scan["scan_id"][:8],
                        "Tạo lúc": display_time(scan["created_at"]),
                        "Mục tiêu": scan["target"],
                        "Trạng thái": SCAN_LABELS.get(scan["status"], scan["status"]),
                        "URL có phản hồi": f"{scan['completed']}/{scan['total']}",
                    }
                    for scan in choices.values()
                ],
                hide_index=True,
                height=200,
            )

    if not choices:
        st.info("Không có lượt quét phù hợp. Hãy xóa hoặc đổi từ khóa.")
        return None

    if st.session_state.get("selected_scan") not in choices:
        st.session_state["selected_scan"] = next(iter(choices))

    def scan_label(scan_id):
        scan = choices[scan_id]
        target = scan["targets"][0] if len(scan["targets"]) == 1 else f"{scan['total']} URL"
        return f"{display_time(scan['created_at'])} · {target} · {scan_id[:8]}"

    selected_id = st.selectbox(
        "Lượt quét đang xem", list(choices), format_func=scan_label, key="selected_scan",
    )
    return choices[selected_id]


def show_findings(scan, findings, selected_row):
    targets = scan["targets"]
    selected_url = targets[selected_row] if selected_row is not None else None
    findings = [
        finding for finding in findings.values()
        if selected_url is None or selected_url == finding["url"]
    ]
    st.subheader("Phát hiện")
    st.text(selected_url or "Tất cả URL trong lượt này")

    if not findings:
        if scan["status"] in ACTIVE_SCAN_STATUSES:
            st.info("Đang chờ kết quả phân tích.")
        elif scan["status"] == "failed":
            st.info("Lượt quét thất bại. Chưa có kết quả phân tích để hiển thị.")
        elif selected_url is not None and scan["responses"].get(selected_url) is None:
            st.info("URL này chưa có phản hồi được lưu để phân tích.")
        else:
            st.info("Không ghi nhận phát hiện theo các quy tắc đã chạy.")
        return

    counts = Counter(finding["severity"] for finding in findings)
    levels = [level for level in reversed(SEVERITY_LABELS) if counts[level]]
    severity = st.segmented_control(
        "Mức độ phát hiện",
        ["all", *levels],
        default="all",
        format_func=lambda level: (
            f"Tất cả ({len(findings)})" if level == "all"
            else f"{SEVERITY_LABELS[level]} ({counts[level]})"
        ),
        key=f"finding_severity_{scan['scan_id']}_{selected_row}",
    ) or "all"

    visible = [item for item in findings if severity in {"all", item["severity"]}]
    visible.sort(key=lambda item: SEVERITY_RANK.get(item["severity"], -1), reverse=True)
    for index, item in enumerate(visible):
        rule = item["rule_id"]
        title = RULE_TITLES.get(rule, rule)
        severity_label = SEVERITY_LABELS.get(item["severity"], item["severity"])
        with st.expander(
            f"{severity_label} · {title} · #{item['finding_id']}", expanded=index == 0
        ):
            show_finding_detail(item)


def show_finding_detail(finding):
    st.text(f"URL: {finding['url']}")
    st.caption(f"Quy tắc · {finding['rule_id']}")
    st.text(f"Bằng chứng: {finding['evidence'] or '—'}")
    st.text(f"Khắc phục: {finding['recommendation']}")


def show_alerts(alerts, findings):
    if not alerts:
        st.info("Không có cảnh báo phù hợp với bộ lọc.")
        return

    for alert in alerts:
        alert_id = alert["alert_id"]
        status = alert["status"]
        finding = findings[alert["finding_id"]]
        label = ALERT_LABELS.get(status, status)
        rule = finding["rule_id"]
        severity = SEVERITY_LABELS.get(alert["severity"], alert["severity"])
        with st.expander(f"{label} · {severity} · {RULE_TITLES.get(rule, rule)} · #{alert_id}"):
            st.caption(f"Phát hiện #{finding['finding_id']} · Cập nhật {display_time(alert['updated_at'])}")
            show_finding_detail(finding)

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


def show_scan_targets(scan, findings):
    finding_counts = Counter(finding["url"] for finding in findings.values())
    responses = scan["responses"]
    waiting = scan["status"] in ACTIVE_SCAN_STATUSES
    rows = []
    for url in scan["targets"]:
        status_code = responses.get(url)
        if status_code is not None:
            result = "Có phản hồi"
        elif url in responses:
            result = "Không nhận phản hồi"
        else:
            result = "Chờ kết quả" if waiting else "Chưa có kết quả lưu"
        rows.append({
            "URL mục tiêu": url,
            "Kết quả": result,
            "Mã HTTP": status_code,
            "Phát hiện": finding_counts[url] if url in finding_counts or status_code is not None else None,
        })

    st.subheader("Mục tiêu")
    if not rows:
        st.info("Lượt này chưa có URL mục tiêu.")
        return None

    st.caption("Chọn một dòng để lọc phát hiện. Bỏ chọn để xem tất cả.")
    event = st.dataframe(
        rows,
        key=f"scan_targets_{scan['scan_id']}",
        on_select="rerun",
        selection_mode="single-row",
        hide_index=True,
        column_config={
            "URL mục tiêu": st.column_config.TextColumn(width=235),
            "Kết quả": st.column_config.TextColumn(width=110),
            "Mã HTTP": st.column_config.NumberColumn(width=65, format="%d"),
            "Phát hiện": st.column_config.NumberColumn(width=70, format="%d"),
        },
    )
    if event.selection.rows:
        index = event.selection.rows[0]
        if 0 <= index < len(rows):
            return index
    return None


def show_alert_panel(alerts, findings, active):
    if not alerts:
        st.info("Đang chờ kết quả phân tích." if active else "Không có cảnh báo cho lượt này.")
        return

    severity_col, status_col = st.columns(2)
    severity = severity_col.selectbox(
        "Mức độ cảnh báo", ["Tất cả", *SEVERITY_LABELS],
        format_func=lambda value: SEVERITY_LABELS.get(value, value),
        key="alert_severity",
    )
    alert_status = status_col.selectbox(
        "Trạng thái cảnh báo", ["Tất cả", *ALERT_LABELS],
        format_func=lambda value: ALERT_LABELS.get(value, value),
        key="alert_status",
    )
    show_alerts([
        alert for alert in alerts
        if (severity == "Tất cả" or alert["severity"] == severity)
        and (alert_status == "Tất cả" or alert["status"] == alert_status)
    ], findings)


def show_scan_report(scan, findings, alerts):
    status = scan["status"]
    active = status in ACTIVE_SCAN_STATUSES
    with st.container(border=True):
        heading, actions = st.columns([3, 2], vertical_alignment="center")
        with heading:
            st.header("Kết quả lượt quét")
            st.badge(SCAN_LABELS.get(status, status), color=SCAN_COLORS.get(status, "gray"))
            st.caption(f"Lượt {scan['scan_id'][:8]} · {display_time(scan['created_at'])} (UTC+7)")
        with actions, st.container(horizontal=True, horizontal_alignment="right"):
            st.button("Tải lại kết quả", key="refresh_results", icon=":material/refresh:")
            with st.popover("Thông tin lượt"):
                st.caption("Mã lượt quét đầy đủ")
                st.code(scan["scan_id"], language=None)
                st.text(f"Tạo lúc: {display_time(scan['created_at'])}")
                st.text(f"Bắt đầu: {display_time(scan['started_at'])}")
                st.text(f"Kết thúc: {display_time(scan['finished_at'])}")

        if status == "queued":
            st.info("Đã vào hàng đợi. Trạng thái tự cập nhật. Nếu chờ lâu, hãy kiểm tra worker đã chạy.")
        elif status == "running":
            st.info("Worker đang xử lý. Kết quả sẽ tự cập nhật.")
        if scan["error"]:
            st.warning("Lượt quét gặp lỗi. Xem thông tin bên dưới để kiểm tra.")
            st.text(f"Thông tin lỗi: {scan['error']}")

        metrics = st.columns(3)
        metrics[0].metric("URL có phản hồi", f"{scan['completed']} / {scan['total']}", border=True)
        metrics[1].metric("Phát hiện", len(findings) if findings or not active else "—", border=True)
        new_alerts = sum(alert["status"] == "open" for alert in alerts)
        metrics[2].metric("Cảnh báo mới", new_alerts if alerts or not active else "—", border=True)

        results_tab, alerts_tab = st.tabs(["Kết quả theo URL", f"Cảnh báo ({len(alerts)})"])
        with results_tab:
            target_col, findings_col = st.columns([5, 6], gap="medium")
            with target_col:
                selected_row = show_scan_targets(scan, findings)
            with findings_col:
                show_findings(scan, findings, selected_row)
        with alerts_tab:
            show_alert_panel(alerts, findings, active)


def show_selected_scan(scan_id, *, watching=False):
    try:
        report = load_scan_report(scan_id)
    except (sqlite3.Error, ValueError, TypeError) as error:
        st.error(f"Không thể đọc kết quả lượt quét: {error}")
        return

    if report is None:
        st.info("Lượt quét này không còn trong lịch sử.")
        return

    scan, findings, alerts = report
    if watching and scan["status"] not in ACTIVE_SCAN_STATUSES:
        st.rerun()
    show_scan_report(scan, findings, alerts)


@st.fragment(run_every=SCAN_REFRESH_SECONDS)
def watch_scan(scan_id):
    show_selected_scan(scan_id, watching=True)


def main():
    st.set_page_config(
        page_title="Web Security Scanner Dashboard",
        layout="wide"
    )

    with st.container(horizontal=True, horizontal_alignment="center"):
        with st.container(width=1200):
            show_dashboard()


def show_dashboard():
    st.title("Bảng điều khiển kiểm tra web")
    try:
        init_db(DB_PATH)
        scans = load_scan_history()
        with st.expander("Tạo lượt quét", expanded=not scans, icon=":material/add:"):
            new_scan_id = show_scan_controls()
        if new_scan_id:
            scans = load_scan_history()

    except sqlite3.Error as error:
        st.error(f"Không thể đọc database: {error}")
        st.info(
            "Hãy kiểm tra quyền đọc và ghi tệp security_monitoring.db."
        )
        return

    except (json.JSONDecodeError, TypeError) as error:
        st.error(f"Dữ liệu trong database không hợp lệ: {error}")
        return

    if not scans:
        st.info("Chưa có lượt quét. Chọn trang demo hoặc nhập URL để bắt đầu.")
        return

    scan = select_scan(scans)
    if scan is None:
        return

    if scan["status"] in ACTIVE_SCAN_STATUSES:
        watch_scan(scan["scan_id"])
    else:
        show_selected_scan(scan["scan_id"])


if __name__ == "__main__":
    main()
