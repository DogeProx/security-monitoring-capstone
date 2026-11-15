
import os
import tempfile
import unittest

from contextlib import closing
from datetime import datetime, timezone, timedelta

from storage.db import (
    create_due_scheduled_jobs,
    create_scheduled_scan,
    get_connection,
    init_db,
    set_scheduled_scan_status,
)


class TestScheduler(unittest.TestCase):

    def setUp(self):
        """Tạo database tạm thời cho mỗi bài test."""

        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(
            self.temp_dir.name,
            "test_scheduler.db"
        )

        init_db(self.db_path)

        self.targets = [
            "http://127.0.0.1:5000/secure",
            "http://127.0.0.1:5000/vuln-headers"
        ]

        self.allowed_hosts = [
            "127.0.0.1"
        ]

    def tearDown(self):
        """Xóa database tạm sau khi test."""

        self.temp_dir.cleanup()

    def create_schedule(self, name="Test schedule", interval=60):
        """Tạo một lịch quét thử nghiệm."""

        return create_scheduled_scan(
            self.db_path,
            name,
            self.targets,
            self.allowed_hosts,
            interval
        )

    def set_next_run(self, schedule_id, next_run):
        """Chỉnh thời gian chạy tiếp theo để mô phỏng lịch quá hạn."""

        with closing(get_connection(self.db_path)) as conn, conn:
            conn.execute("""
                UPDATE scheduled_scans
                SET next_run_at = ?
                WHERE schedule_id = ?
            """, (
                next_run.astimezone(timezone.utc).isoformat(
                    timespec="seconds"
                ),
                schedule_id
            ))

    def count_rows(self, table):
        """Đếm số bản ghi trong bảng."""

        allowed_tables = {
            "scan_jobs",
            "scheduled_scan_runs",
            "scheduled_scans"
        }

        if table not in allowed_tables:
            raise ValueError("Tên bảng không hợp lệ.")

        with closing(get_connection(self.db_path)) as conn:
            row = conn.execute(
                f"SELECT COUNT(*) AS total FROM {table}"
            ).fetchone()

            return row["total"]

    def get_next_run(self, schedule_id):
        """Lấy thời gian chạy tiếp theo."""

        with closing(get_connection(self.db_path)) as conn:
            row = conn.execute("""
                SELECT next_run_at
                FROM scheduled_scans
                WHERE schedule_id = ?
            """, (schedule_id,)).fetchone()

            return row["next_run_at"]

    def test_overdue_schedule_creates_only_one_job(self):
        """
        Lịch bị quá hạn nhiều chu kỳ
        nhưng chỉ được tạo một Scan Job.
        """

        schedule_id = self.create_schedule(interval=60)

        now = datetime.now(timezone.utc)
        overdue_time = now - timedelta(minutes=30)

        self.set_next_run(
            schedule_id,
            overdue_time
        )

        created_jobs = create_due_scheduled_jobs(
            self.db_path,
            now=now
        )

        self.assertEqual(len(created_jobs), 1)
        self.assertEqual(self.count_rows("scan_jobs"), 1)
        self.assertEqual(
            self.count_rows("scheduled_scan_runs"),
            1
        )

    def test_next_run_is_now_plus_interval_not_old_due_time(self):
        """
        next_run_at phải bằng now + interval,
        không phải mốc chạy cũ + interval.
        """

        schedule_id = self.create_schedule(interval=60)

        now = datetime.now(timezone.utc)
        overdue_time = now - timedelta(minutes=30)

        self.set_next_run(
            schedule_id,
            overdue_time
        )

        create_due_scheduled_jobs(
            self.db_path,
            now=now
        )

        expected_next_run = (
            now.astimezone(timezone.utc)
            + timedelta(seconds=60)
        ).isoformat(timespec="seconds")

        actual_next_run = self.get_next_run(
            schedule_id
        )

        self.assertEqual(
            actual_next_run,
            expected_next_run
        )

    def test_disabled_schedule_does_not_create_job(self):
        """Lịch đã tắt không được tạo Scan Job."""

        schedule_id = self.create_schedule(interval=60)

        now = datetime.now(timezone.utc)
        overdue_time = now - timedelta(minutes=30)

        self.set_next_run(
            schedule_id,
            overdue_time
        )

        set_scheduled_scan_status(
            self.db_path,
            schedule_id,
            False
        )

        created_jobs = create_due_scheduled_jobs(
            self.db_path,
            now=now
        )

        self.assertEqual(len(created_jobs), 0)
        self.assertEqual(self.count_rows("scan_jobs"), 0)
        self.assertEqual(
            self.count_rows("scheduled_scan_runs"),
            0
        )

    def test_two_due_schedules_create_two_jobs(self):
        """Hai lịch đến hạn phải tạo đúng hai Scan Job."""

        schedule_id_1 = self.create_schedule(
            name="Schedule 1",
            interval=60
        )

        schedule_id_2 = self.create_schedule(
            name="Schedule 2",
            interval=120
        )

        now = datetime.now(timezone.utc)
        overdue_time = now - timedelta(minutes=30)

        self.set_next_run(
            schedule_id_1,
            overdue_time
        )

        self.set_next_run(
            schedule_id_2,
            overdue_time
        )

        created_jobs = create_due_scheduled_jobs(
            self.db_path,
            now=now
        )

        self.assertEqual(len(created_jobs), 2)
        self.assertEqual(self.count_rows("scan_jobs"), 2)
        self.assertEqual(
            self.count_rows("scheduled_scan_runs"),
            2
        )

    def test_second_check_does_not_create_duplicate_job(self):
        """
        Sau khi đã tạo job, kiểm tra lại trước thời hạn tiếp theo
        không được tạo thêm job.
        """

        schedule_id = self.create_schedule(interval=60)

        now = datetime.now(timezone.utc)
        overdue_time = now - timedelta(minutes=30)

        self.set_next_run(
            schedule_id,
            overdue_time
        )

        first_result = create_due_scheduled_jobs(
            self.db_path,
            now=now
        )

        second_result = create_due_scheduled_jobs(
            self.db_path,
            now=now + timedelta(seconds=10)
        )

        self.assertEqual(len(first_result), 1)
        self.assertEqual(len(second_result), 0)
        self.assertEqual(self.count_rows("scan_jobs"), 1)

    def test_future_schedule_does_not_create_job(self):
        """Lịch chưa đến hạn không được tạo Scan Job."""

        schedule_id = self.create_schedule(interval=60)

        now = datetime.now(timezone.utc)
        future_time = now + timedelta(minutes=30)

        self.set_next_run(
            schedule_id,
            future_time
        )

        created_jobs = create_due_scheduled_jobs(
            self.db_path,
            now=now
        )

        self.assertEqual(len(created_jobs), 0)
        self.assertEqual(self.count_rows("scan_jobs"), 0)
        self.assertEqual(
            self.count_rows("scheduled_scan_runs"),
            0
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
