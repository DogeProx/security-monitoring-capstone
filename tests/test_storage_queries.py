from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import TestCase

from storage.db import (
    create_scan_job,
    get_alerts_with_details,
    get_all_scans,
    get_connection,
    get_pending_scan_job,
    get_report_data,
    init_db,
    recover_stuck_jobs,
    record_finding_and_alert,
    save_scan_report,
    transition_alert,
    update_scan_progress,
    update_scan_status,
)


class StorageQueriesTests(TestCase):
    def test_worker_recovery_requeues_only_running_jobs(self):
        with TemporaryDirectory() as folder:
            database = Path(folder) / "recovery.db"
            init_db(database)
            origin = "http://127.0.0.1:5000"
            targets = [origin + "/secure"]
            finished = create_scan_job(database, targets, [origin])
            running = create_scan_job(database, targets, [origin])
            waiting = create_scan_job(database, targets, [origin])
            update_scan_status(database, finished, "COMPLETED")
            self.assertEqual(get_pending_scan_job(database, running)["scan_id"], running)
            update_scan_progress(database, running, 1, 1)

            self.assertEqual(recover_stuck_jobs(database), 1)
            self.assertEqual(recover_stuck_jobs(database), 0)

            with closing(get_connection(database)) as conn:
                states = {
                    row["scan_id"]: (row["status"], row["started_at"], row["completed"])
                    for row in conn.execute("SELECT scan_id, status, started_at, completed FROM scan_jobs")
                }
            self.assertEqual(states[finished][0], "COMPLETED")
            self.assertEqual(states[running], ("PENDING", None, 0))
            self.assertEqual(states[waiting], ("PENDING", None, 0))
            self.assertEqual(get_pending_scan_job(database, running)["scan_id"], running)

    def test_queries_after_concurrent_writes_and_alert_transition(self):
        with TemporaryDirectory() as folder:
            database = Path(folder) / "test.db"
            init_db(database)
            self.assertEqual(get_all_scans(database), [])
            self.assertEqual(get_alerts_with_details(database), [])
            self.assertEqual(get_report_data(database), [])

            scan_id = "test-scan"
            url = "http://127.0.0.1:5000/"
            save_scan_report(database, {
                "scan_id": scan_id,
                "started_at": "2026-11-18T00:00:00+00:00",
                "finished_at": "2026-11-18T00:00:01+00:00",
                "status": "completed",
                "results": [{"url": url, "status_code": 200}],
            })

            def record(rule_id):
                severity = "HIGH" if rule_id == "HIGH-RULE" else "LOW"
                return record_finding_and_alert(database, scan_id, url, rule_id, severity, "demo")

            with ThreadPoolExecutor(max_workers=4) as writers:
                finding_ids = list(writers.map(record, ["HIGH-RULE"] * 8 + ["LOW-RULE"]))
            self.assertEqual(len(set(finding_ids[:8])), 1)
            self.assertNotEqual(finding_ids[0], finding_ids[-1])

            self.assertEqual([row["scan_id"] for row in get_all_scans(database)], [scan_id])
            alerts = get_alerts_with_details(database)
            self.assertEqual(len(alerts), 1)
            self.assertEqual((alerts[0]["status"], alerts[0]["url"]), ("NEW", url))
            self.assertTrue(transition_alert(database, alerts[0]["alert_id"], "RESOLVED"))
            self.assertEqual(get_alerts_with_details(database)[0]["status"], "RESOLVED")
            self.assertEqual(
                {row["rule_id"]: row["alert_status"] for row in get_report_data(database)},
                {"HIGH-RULE": "RESOLVED", "LOW-RULE": None},
            )
