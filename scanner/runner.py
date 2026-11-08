
from datetime import datetime, timezone
from uuid import uuid4

from scanner.client import scan_url


def run_scan(
    targets,
    allowed_hosts,
    timeout=5,
    max_redirects=5,
    progress_callback=None
):
    """
    Coordinate scanning multiple URLs.
    """

    scan_id = str(uuid4())
    started_at = datetime.now(timezone.utc).isoformat()

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

    finished_at = datetime.now(timezone.utc).isoformat()

    return {
        "scan_id": scan_id,
        "status": "completed",
        "started_at": started_at,
        "finished_at": finished_at,
        "summary": {
            "total": total,
            "completed": completed,
            "failed": failed
        },
        "results": results
    }
