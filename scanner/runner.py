
from datetime import datetime, timezone
from uuid import uuid4

from scanner.client import scan_url


def run_scan(
    targets,
    allowed_hosts,
    timeout=5,
    max_redirects=5,
    progress_callback=None,
    scan_id=None
):
    """Điều phối quá trình quét nhiều URL."""

    scan_id = scan_id or str(uuid4())
    started_at = datetime.now(timezone.utc).isoformat()

    allowed_hosts = tuple(allowed_hosts)
    results = []
    total = len(targets)

    for index, url in enumerate(targets, start=1):
        result = scan_url(
            url=url,
            allowed_hosts=allowed_hosts,
            timeout=timeout,
            max_redirects=max_redirects
        )

        result["scan_id"] = scan_id
        results.append(result)

        if progress_callback:
            progress_callback(index, total, result)

    completed = sum(
        1 for item in results
        if item["status"] == "completed"
    )

    failed = total - completed

    if total > 0 and completed == total:
        status = "completed"
    elif completed > 0:
        status = "partial"
    else:
        status = "failed"

    finished_at = datetime.now(timezone.utc).isoformat()

    return {
        "scan_id": scan_id,
        "status": status,
        "started_at": started_at,
        "finished_at": finished_at,
        "summary": {
            "total": total,
            "completed": completed,
            "failed": failed
        },
        "results": results
    }
