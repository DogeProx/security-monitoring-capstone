from contextlib import closing, contextmanager
import csv
from datetime import datetime, timedelta, timezone
from http.server import ThreadingHTTPServer
from pathlib import Path
import sqlite3
from tempfile import TemporaryDirectory
from threading import Thread
from unittest import TestCase

from Reporter.sqlite_exporter import SQLiteReportExporter
from Web_demo.app import DemoHandler
from storage.db import (
    create_due_scheduled_jobs,
    create_scan_job,
    create_scheduled_scan,
    init_db,
)
from worker import process_one_job


@contextmanager
def demo_server():
    with ThreadingHTTPServer(("127.0.0.1", 0), DemoHandler) as server:
        thread = Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            yield f"http://127.0.0.1:{server.server_port}"
        finally:
            server.shutdown()
            thread.join()


class TestWeek4(TestCase):
    def setUp(self):
        directory = TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.db = self.root / "demo.db"
        init_db(self.db)

    def run_pages(self, origin, paths, rules_config=None):
        scan_id = create_scan_job(self.db, [origin + path for path in paths], [origin])
        report = process_one_job(scan_id, db_path=self.db, rules_config=rules_config)
        self.assertIsNotNone(report)
        return report

    def rules_for(self, report, url):
        with closing(sqlite3.connect(self.db)) as conn:
            rows = conn.execute(
                "SELECT rule_id FROM findings WHERE scan_id = ? AND url = ?",
                (report["scan_id"], url),
            )
            return {row[0] for row in rows}

    def test_demo_edge_cases(self):
        expected = {
            "/secure": set(),
            "/api/data": {"SEC-HDR-XCTO"},
            "/public-page": set(),
            "/vuln-multi": {"SEC-HDR-CSP", "SEC-HDR-XCTO", "SEC-CKI-HTTPONLY"},
        }
        with demo_server() as origin:
            report = self.run_pages(origin, expected)
        self.assertEqual(report["status"], "completed")
        for path, rules in expected.items():
            with self.subTest(path=path):
                self.assertEqual(self.rules_for(report, origin + path), rules)

    def test_offline_demo(self):
        with demo_server() as origin:
            pass
        report = self.run_pages(origin, ["/secure"])
        self.assertEqual(report["status"], "failed")
        self.assertEqual(report["summary"]["failed"], 1)
        self.assertEqual(self.rules_for(report, origin + "/secure"), set())

    def test_rule_toggle_changes_persisted_findings(self):
        with demo_server() as origin:
            report = self.run_pages(origin, ["/vuln-multi"], {
                "SEC-HDR-CSP": False,
                "SEC-HDR-XCTO": True,
                "SEC-CKI-HTTPONLY": True,
            })
        self.assertEqual(self.rules_for(report, origin + "/vuln-multi"),
                         {"SEC-HDR-XCTO", "SEC-CKI-HTTPONLY"})

    def test_scheduled_job_and_reporting_without_dashboard(self):
        with demo_server() as origin:
            create_scheduled_scan(self.db, "Local demo", [origin + "/vuln-multi"], [origin], 60)
            due = datetime.now(timezone.utc) + timedelta(minutes=2)
            jobs = create_due_scheduled_jobs(self.db, now=due)
            self.assertEqual(len(jobs), 1)
            self.assertEqual(create_due_scheduled_jobs(self.db, now=due), [])
            report = process_one_job(jobs[0], db_path=self.db)
        self.assertEqual(report["status"], "completed")

        exporter = SQLiteReportExporter(db_path=self.db, output_dir=self.root)
        with Path(exporter.export_csv(scan_id=jobs[0])).open(encoding="utf-8-sig", newline="") as stream:
            self.assertEqual(len(list(csv.DictReader(stream))), 3)
        html = Path(exporter.export_html(scan_id=jobs[0])).read_text(encoding="utf-8")
        self.assertIn("SEC-CKI-HTTPONLY", html)
        with closing(sqlite3.connect(self.db)) as conn:
            self.assertEqual(conn.execute("SELECT count(*) FROM alerts").fetchone(), (1,))
