from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import TestCase

from streamlit.testing.v1 import AppTest

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
            self.assertEqual(process_one_job(db_path=self.db)["status"], "completed")
            self.refresh(app)
        self.assertEqual([item.value for item in app.metric], ["1", "1", "0", "0"])
        self.assertTrue(any("Không có phát hiện" in item.value for item in app.info))
        self.assertTrue(any("Không có cảnh báo" in item.value for item in app.info))

    def test_findings_and_alert_workflow(self):
        with demo_server() as origin:
            app = self.start_dashboard(origin)
            self.queue(app, "Tất cả trang demo")
            self.assertEqual(process_one_job(db_path=self.db)["status"], "completed")
            self.refresh(app)

        self.assertEqual([item.value for item in app.metric], ["1", "3", "5", "1"])
        self.assertTrue(any("Bằng chứng" in item.value and "HttpOnly" in item.value for item in app.text))
        app.button(key="ack_1").click().run()
        self.assertFalse(app.exception)
        self.assertTrue(any("Đã xác nhận xem cảnh báo" in item.value for item in app.text))
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
        self.assertEqual([item.value for item in app.metric], ["1", "1", "0", "0"])
        self.assertIn("**Trạng thái:** Thất bại", [item.value for item in app.markdown])
        self.assertTrue(any(
            item.value.startswith("**Thông tin lỗi:** ") and item.value != "**Thông tin lỗi:** —"
            for item in app.markdown
        ))
