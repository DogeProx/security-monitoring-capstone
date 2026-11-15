from storage.db import init_db, create_scan_job

DB_PATH = "security_monitoring.db"

init_db(DB_PATH)

for i in range(2):
    scan_id = create_scan_job(
        db_path=DB_PATH,
        targets=["https://example.com"],
        allowed_hosts=["example.com"]
    )

    print(f"Created job {i + 1}: {scan_id}")