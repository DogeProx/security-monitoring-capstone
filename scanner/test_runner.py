
from scanner.runner import run_scan
import json


targets = [
    "https://example.com",
    "https://google.com",
    "https://example.org"
]

allowed_hosts = [
    "example.com",
    "example.org"
]


def show_progress(current, total, result):
    print(
        f"[{current}/{total}] "
        f"{result['url']} -> {result['status']}"
    )


report = run_scan(
    targets=targets,
    allowed_hosts=allowed_hosts,
    progress_callback=show_progress
)

print("\n========== SCAN REPORT ==========")
print(json.dumps(report, indent=4, ensure_ascii=False))
