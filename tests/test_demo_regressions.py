import csv
from contextlib import closing
from pathlib import Path
import sqlite3
from tempfile import TemporaryDirectory
from unittest import TestCase
from unittest.mock import patch

from detection_rules.rules import analyze_response
from Reporter.Export import export_csv, export_html, load_report
from storage.db import create_scan_job, init_db, save_scan_report
from worker import process_one_job


class DemoRegressionTests(TestCase):
    def test_httponly_checks_the_session_cookie_itself(self):
        findings = analyze_response({
            "headers": {
                "Content-Type": "text/html",
                "Content-Security-Policy": "default-src 'self'",
                "X-Content-Type-Options": "nosniff",
            },
            "cookies": [
                {"name": "session_id", "httponly": False},
                {"name": "preferences", "httponly": True},
            ],
        })
        self.assertEqual([item["rule_id"] for item in findings], ["SEC-CKI-HTTPONLY"])

    def test_partial_scan_counts_only_successes_and_retries_replace_results(self):
        with TemporaryDirectory() as temp_dir:
            database = Path(temp_dir) / "test.db"
            init_db(database)
            urls = ["http://127.0.0.1:5000/", "http://127.0.0.1:5001/"]
            scan_id = create_scan_job(database, urls, ["http://127.0.0.1:5000"])
            responses = [
                {
                    "url": urls[0], "status": "completed", "status_code": 200,
                    "headers": {
                        "Content-Type": "text/html",
                        "Content-Security-Policy": "default-src 'self'",
                        "X-Content-Type-Options": "nosniff",
                    },
                    "cookies": [{"name": "session_id", "httponly": False}],
                },
                {"url": urls[1], "status": "failed", "status_code": None},
            ]
            with patch("scanner.runner.scan_url", side_effect=responses):
                report = process_one_job(scan_id, db_path=database)

            self.assertEqual(report["status"], "partial")
            save_scan_report(database, report)
            with closing(sqlite3.connect(database)) as connection:
                job = connection.execute("SELECT status, completed, total FROM scan_jobs").fetchone()
                self.assertEqual(job, ("PARTIAL", 1, 2))
                self.assertEqual(connection.execute("SELECT count(*) FROM results").fetchone()[0], 2)

            rows = load_report(database)
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]["Trạng thái cảnh báo"], "Mới")
            self.assertIn("HttpOnly", rows[0]["Cách khắc phục"])

    def test_exports_handle_empty_data_and_escape_html_cells(self):
        with TemporaryDirectory() as temp_dir:
            csv_path = Path(temp_dir) / "report.csv"
            html_path = Path(temp_dir) / "report.html"
            export_csv([], csv_path)
            export_html([], html_path)
            with csv_path.open(encoding="utf-8-sig", newline="") as stream:
                self.assertEqual(len(list(csv.reader(stream))), 1)
            self.assertIn("<tbody></tbody>", html_path.read_text(encoding="utf-8"))

            export_html([{"<evidence>": "<b>unsafe</b>"}], html_path)
            html = html_path.read_text(encoding="utf-8")
            self.assertIn("&lt;evidence&gt;", html)
            self.assertIn("&lt;b&gt;unsafe&lt;/b&gt;", html)
