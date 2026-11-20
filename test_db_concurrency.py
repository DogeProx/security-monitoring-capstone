import multiprocessing
import os
import tempfile
from contextlib import closing
from datetime import datetime, timezone

from storage.db import (
    create_scan_job,
    get_connection,
    get_pending_scan_job,
    init_db,
    record_finding_and_alert,
    save_scan_report,
)


def worker_process(db_path, scan_id, worker_id, writes_per_worker, result_queue):
    """Mỗi tiến trình vừa tranh nhận job vừa ghi liên tục findings + alerts."""
    claimed_jobs = []
    errors = []

    try:
        while True:
            job = get_pending_scan_job(db_path)
            if job is None:
                break
            claimed_jobs.append(job["scan_id"])

        for i in range(writes_per_worker):
            record_finding_and_alert(
                db_path=db_path,
                scan_id=scan_id,
                url=f"http://demo.local/worker-{worker_id}/page-{i}",
                rule_id=f"RULE_{worker_id}_{i}",
                severity="HIGH",
                evidence=f"Bang chung tu tien trinh {worker_id}, lan {i}",
                alert_threshold="HIGH",
            )
    except Exception as exc:
        errors.append(f"Worker {worker_id} loi: {type(exc).__name__}: {exc}")

    result_queue.put((worker_id, claimed_jobs, errors))


def run_concurrency_test():
    num_processes = 6
    writes_per_worker = 10
    total_jobs = 12

    with tempfile.TemporaryDirectory() as tmp_dir:
        db_path = os.path.join(tmp_dir, "test_concurrent.db")
        init_db(db_path)

        scan_id = "scan-concurrency-test"
        now = datetime.now(timezone.utc).isoformat()
        save_scan_report(
            db_path,
            {
                "scan_id": scan_id,
                "started_at": now,
                "finished_at": None,
                "status": "RUNNING",
                "results": [],
            },
        )

        for i in range(total_jobs):
            create_scan_job(
                db_path,
                targets=[f"http://demo.local/job-{i}"],
                allowed_hosts=["demo.local"],
            )

        queue = multiprocessing.Queue()
        processes = [
            multiprocessing.Process(
                target=worker_process,
                args=(db_path, scan_id, wid, writes_per_worker, queue),
            )
            for wid in range(num_processes)
        ]

        for p in processes:
            p.start()
        for p in processes:
            p.join()

        all_claimed = []
        all_errors = []
        for _ in range(num_processes):
            _, claimed, errs = queue.get()
            all_claimed.extend(claimed)
            all_errors.extend(errs)

        with closing(get_connection(db_path)) as conn:
            findings_count = conn.execute("SELECT COUNT(*) FROM findings").fetchone()[0]
            alerts_count = conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
            logs_count = conn.execute("SELECT COUNT(*) FROM audit_logs").fetchone()[0]

        expected_writes = num_processes * writes_per_worker

        print("=== KET QUA KIEM THU NHIEU TIEN TRINH GHI DONG THOI ===")
        print(f"- So tien trinh chay song song : {num_processes}")
        print(f"- So loi (database locked...)  : {len(all_errors)}")
        print(f"- Job da nhan / Tong job       : {len(all_claimed)} / {total_jobs} (khong trung: {len(set(all_claimed))})")
        print(f"- So findings ghi thanh cong   : {findings_count} / {expected_writes}")
        print(f"- So alerts tu dong tao        : {alerts_count} / {expected_writes}")
        print(f"- So audit_logs tu dong ghi    : {logs_count} / {expected_writes}")

        if all_errors:
            print("Chi tiet loi:", all_errors)

        assert len(all_errors) == 0, "Co loi xay ra khi ghi dong thoi!"
        assert len(all_claimed) == total_jobs and len(set(all_claimed)) == total_jobs, "Nhan trung hoac sot job!"
        assert findings_count == expected_writes, "Thieu du lieu findings!"
        assert alerts_count == expected_writes, "Thieu du lieu alerts!"
        assert logs_count == expected_writes, "Thieu du lieu audit_logs!"
        print(">>> PASS: SQLite xu ly ghi dong thoi an toan, khong khoa DB, khong trung job!")


if __name__ == "__main__":
    run_concurrency_test()