from tests.test_week4_edge_cases import demo_server
from Reporter.sqlite_exporter import SQLiteReportExporter
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import FunctionTestCase
from storage.db import create_scan_job, init_db
from worker import process_one_job


def test_week3_full_pipeline():
    with TemporaryDirectory() as directory, demo_server() as origin:
        db = Path(directory) / "demo.db"
        init_db(db)
        paths = ("/secure", "/vuln-headers", "/vuln-cookie")
        scan_id = create_scan_job(db, [origin + path for path in paths], [origin])
        report = process_one_job(scan_id, db_path=db)
        assert report["status"] == "completed"
        exporter = SQLiteReportExporter(db_path=db, output_dir=directory)
        rows = exporter.fetch_findings_with_alerts(scan_id=scan_id)
        assert len(rows) == 5
        assert Path(exporter.export_csv(scan_id=scan_id)).stat().st_size > 0
        assert Path(exporter.export_html(scan_id=scan_id)).stat().st_size > 0


def load_tests(loader, standard_tests, pattern):
    standard_tests.addTest(FunctionTestCase(test_week3_full_pipeline))
    return standard_tests


if __name__ == "__main__":
    test_week3_full_pipeline()
