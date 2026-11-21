from contextlib import closing
from pathlib import Path
import sqlite3
from tempfile import TemporaryDirectory
from unittest import TestCase

from storage.db import create_scan_job, init_db
from tests.test_week4_edge_cases import demo_server
from worker import process_one_job


class ScannerWeek6Tests(TestCase):
    def setUp(self):
        directory = TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.db = Path(directory.name) / "scanner.db"
        init_db(self.db)

    def run_scan(self, targets, origins):
        scan_id = create_scan_job(self.db, targets, origins)
        report = process_one_job(scan_id, db_path=self.db)
        self.assertIsNotNone(report)
        with closing(sqlite3.connect(self.db)) as conn:
            job = conn.execute(
                "SELECT status, completed, total FROM scan_jobs WHERE scan_id = ?", (scan_id,)
            ).fetchone()
        self.assertEqual(job, (
            report["status"].upper(),
            report["summary"]["completed"],
            report["summary"]["total"],
        ))
        return report

    def test_http500_is_a_received_response(self):
        with demo_server() as origin:
            report = self.run_scan([origin + "/error"], [origin])
        self.assertEqual(report["status"], "completed")
        self.assertEqual(report["results"][0]["status_code"], 500)
        self.assertEqual(report["summary"], {"total": 1, "completed": 1, "failed": 0})
        print("PASS HTTP 500: response code 500; scan COMPLETED; successful URLs 1/1.")

    def test_failed_scan_when_server_is_offline(self):
        with demo_server() as offline:
            pass
        report = self.run_scan([offline + "/secure"], [offline])
        self.assertEqual(report["status"], "failed")
        self.assertEqual(report["summary"], {"total": 1, "completed": 0, "failed": 1})
        self.assertTrue(report["results"][0]["error"])
        print("PASS FAILED: offline server; scan FAILED; successful URLs 0/1.")

    def test_partial_scan_with_one_offline_url(self):
        with demo_server() as offline:
            pass
        with demo_server() as origin:
            report = self.run_scan(
                [origin + "/secure", offline + "/secure"], [origin, offline]
            )
        self.assertEqual(report["status"], "partial")
        self.assertEqual(report["summary"], {"total": 2, "completed": 1, "failed": 1})
        print("PASS PARTIAL: one reachable and one offline URL; successful URLs 1/2.")
