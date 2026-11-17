
from storage.db import (
    init_db,
    create_scan_job,
    get_pending_scan_job,
    recover_stuck_jobs
)

DB_PATH = "queue_test.db"

init_db(DB_PATH)

# Tạo job mới
scan_id = create_scan_job(
    DB_PATH,
    ["https://example.com"],
    ["example.com"]
)

print("Created:", scan_id)

# Giả lập Worker nhận job
job = get_pending_scan_job(DB_PATH)
print("Job status: RUNNING")

# Giả lập Worker bị tắt đột ngột
recovered = recover_stuck_jobs(DB_PATH)

print("Recovered jobs:", recovered)
