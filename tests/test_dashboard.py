from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import TestCase, mock

from streamlit.testing.v1 import AppTest

from storage.db import get_pending_scan_job
from tests.test_week4_edge_cases import demo_server
from worker import process_one_job


def dashboard_for_test(database, origin):
    from unittest.mock import patch

    from dashboard import app

    targets = [origin + path for path in ("/secure", "/vuln-headers", "/vuln-cookie")]
    with patch.multiple(app, DB_PATH=database, DEMO_ORIGIN=origin, DEMO_TARGETS=targets):
        app.main()


class DashboardTests(TestCase):
    def setUp(self):
        directory = TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.db = Path(directory.name) / "dashboard.db"

    def start_dashboard(self, origin):
        app = AppTest.from_function(dashboard_for_test, args=(self.db, origin)).run()
        self.assertFalse(app.exception)
        self.assertFalse(app.error)
        return app

    def queue(self, app, selection):
        app.selectbox(key="scan_selection").set_value(selection).run()
        app.button(key="queue_scan").click().run()
        self.assertFalse(app.exception)
        self.assertEqual(len(app.success), 1)

    def refresh(self, app):
        app.button(key="refresh_results").click().run()
        self.assertFalse(app.exception)
        self.assertFalse(app.error)

    def test_empty_dashboard_and_clean_scan(self):
        with demo_server() as origin:
            app = self.start_dashboard(origin)
            self.assertTrue(any("Chưa có lượt quét" in item.value for item in app.info))
            self.queue(app, "/secure")
            self.assertEqual(app.dataframe[-1].value["Kết quả"].tolist(), ["Chờ kết quả"])
            self.assertTrue(any("Đang chờ kết quả phân tích" in item.value for item in app.info))
            self.assertEqual([item.value for item in app.metric], ["0 / 1", "—", "—"])
            self.assertEqual(process_one_job(db_path=self.db)["status"], "completed")
            self.refresh(app)
        self.assertEqual([item.value for item in app.metric], ["1 / 1", "0", "0"])
        self.assertEqual(app.dataframe[-1].value["Mã HTTP"].tolist(), [200])
        self.assertTrue(any("Không ghi nhận phát hiện" in item.value for item in app.info))
        self.assertTrue(any("Không có cảnh báo" in item.value for item in app.info))

    def test_findings_and_alert_workflow(self):
        with demo_server() as origin:
            app = self.start_dashboard(origin)
            self.queue(app, "Tất cả trang demo")
            self.assertEqual(process_one_job(db_path=self.db)["status"], "completed")
            self.refresh(app)

        self.assertEqual([item.value for item in app.metric], ["3 / 3", "5", "1"])
        self.assertTrue(any("Bằng chứng" in item.value and "HttpOnly" in item.value for item in app.text))
        app.button(key="ack_1").click().run()
        self.assertFalse(app.exception)
        self.assertTrue(any("Đã xác nhận xem cảnh báo" in item.value for item in app.text))
        self.assertEqual([item.value for item in app.metric], ["3 / 3", "5", "0"])
        app.button(key="resolve_1").click().run()
        self.assertFalse(app.exception)
        self.assertTrue(any("Đã xử lý cảnh báo" in item.value for item in app.text))

    def test_failed_scan_shows_error_detail(self):
        with demo_server() as origin:
            pass
        app = self.start_dashboard(origin)
        self.queue(app, "/secure")
        self.assertEqual(process_one_job(db_path=self.db)["status"], "failed")
        self.refresh(app)
        self.assertEqual([item.value for item in app.metric], ["0 / 1", "0", "0"])
        self.assertIn(":red-badge[Thất bại]", [item.value for item in app.markdown])
        self.assertEqual(app.dataframe[-1].value["Kết quả"].tolist(), ["Không nhận phản hồi"])
        self.assertTrue(any(
            item.value.startswith("Thông tin lỗi: ") and item.value != "Thông tin lỗi: —"
            for item in app.text
        ))

    def test_custom_url_queue_and_history_selection(self):
        from contextlib import closing
        import sqlite3

        with demo_server() as origin, mock.patch.dict("os.environ", {"DASHBOARD_ALLOWED_ORIGINS": ""}):
            app = self.start_dashboard(origin)
            self.queue(app, "Tất cả trang demo")
            self.assertEqual(process_one_job(db_path=self.db)["status"], "completed")
            self.refresh(app)
            first_id = app.selectbox(key="selected_scan").value
            app.radio[0].set_value("Nhập URL").run()

            self.assertTrue(any(origin in item.value for item in app.caption))
            for invalid, error in (
                ("ftp://example.com", "Nhập tên miền hoặc URL HTTP/HTTPS hợp lệ"),
                ("https://example.com", "chưa có trong phạm vi quét"),
            ):
                app.text_input(key="scan_url").set_value(invalid).run()
                app.button(key="queue_scan").click().run()
                self.assertFalse(app.exception)
                self.assertIn(error, app.error[0].value)
                self.assertIn(origin + "/secure", app.error[0].value)

            app.text_input(key="history_query").set_value(first_id).run()
            app.text_input(key="scan_url").set_value(origin + "/secure").run()
            app.button(key="queue_scan").click().run()
            self.assertFalse(app.exception)
            self.assertEqual(len(app.success), 1)
            second_id = app.selectbox(key="selected_scan").value
            self.assertNotEqual(first_id, second_id)
            self.assertEqual(app.text_input(key="history_query").value, "")

            with closing(sqlite3.connect(self.db)) as conn:
                self.assertEqual(conn.execute("SELECT COUNT(*) FROM scan_jobs").fetchone()[0], 2)

            self.assertEqual(process_one_job(db_path=self.db)["status"], "completed")
            self.refresh(app)
            self.assertEqual([item.value for item in app.metric], ["1 / 1", "0", "0"])
            app.selectbox(key="selected_scan").set_value(first_id).run()
            self.assertEqual([item.value for item in app.metric], ["3 / 3", "5", "1"])

            table_key = f"scan_targets_{first_id}"
            app.session_state[table_key] = {"selection": {"rows": [1]}}
            app.run()
            self.assertFalse(app.exception)
            self.assertIn(f"URL: {origin}/vuln-headers", [item.value for item in app.text])
            self.assertNotIn(f"URL: {origin}/vuln-cookie", [item.value for item in app.tabs[0].text])

            app.session_state[table_key] = {"selection": {"rows": [0]}}
            app.run()
            self.assertTrue(any("Không ghi nhận phát hiện" in item.value for item in app.info))

            app.session_state[table_key] = {"selection": {"rows": []}}
            app.run()
            app.segmented_control(key=f"finding_severity_{first_id}_None").set_value("high").run()
            finding_cards = [item.label for item in app.expander if " · #" in item.label]
            self.assertEqual(len([label for label in finding_cards if label.startswith("Cao ·")]), 1)
            self.assertFalse(any(label.startswith(("Trung bình ·", "Thấp ·")) for label in finding_cards))
            app.selectbox(key="alert_status").set_value("resolved").run()
            self.assertTrue(any("Không có cảnh báo" in item.value for item in app.info))
            self.assertEqual([item.value for item in app.metric], ["3 / 3", "5", "1"])

    def test_configured_origins_are_reloaded_and_used_for_custom_urls(self):
        with demo_server() as origin, demo_server() as extra_origin, mock.patch.dict(
            "os.environ", {"DASHBOARD_ALLOWED_ORIGINS": ""}
        ):
            app = self.start_dashboard(origin)
            app.radio[0].set_value("Nhập URL").run()
            extra_url = extra_origin + "/secure"
            app.text_input(key="scan_url").set_value(extra_url).run()
            app.button(key="queue_scan").click().run()
            self.assertTrue(app.error)

            self.db.with_name("dashboard_origins.txt").write_text(
                f"# Additional origins\n{extra_origin}\nhttps://site.example\n",
                encoding="utf-8-sig",
            )
            app.button(key="queue_scan").click().run()
            self.assertFalse(app.exception)
            self.assertFalse(app.error)
            self.assertTrue(any(extra_origin in item.value for item in app.caption))
            self.assertEqual(process_one_job(db_path=self.db)["status"], "completed")
            self.refresh(app)
            self.assertEqual(app.dataframe[-1].value["Mã HTTP"].tolist(), [200])

            app.text_input(key="scan_url").set_value("site.example/secure").run()
            app.button(key="queue_scan").click().run()
            self.assertFalse(app.exception)
            self.assertFalse(app.error)
            job = get_pending_scan_job(self.db)
            self.assertEqual(job["targets"], ["https://site.example/secure"])
            self.assertEqual(job["allowed_hosts"], ["https://site.example/secure"])
