
# Web Scanner Module

## 1. Purpose

The Scanner module sends HTTP requests to authorized target URLs and collects HTTP response information.

It does not detect vulnerabilities or create alerts.

## 2. Public Interface

```python
from scanner import run_scan
```

### run_scan()

```python
run_scan(
    targets,
    allowed_hosts,
    timeout=5,
    max_redirects=5,
    progress_callback=None
)
```

Parameters:

| Parameter | Type | Description |
|---|---|---|
| targets | list[str] | URLs to scan |
| allowed_hosts | list[str] | Authorized hostnames |
| timeout | int/float | Request timeout in seconds |
| max_redirects | int | Maximum redirects |
| progress_callback | callable/None | Optional progress callback |

### Progress callback

```python
def show_progress(current, total, result):
    print(current, total, result["url"])
```

## 3. Scan Result

Each result contains:

| Field | Type | Description |
|---|---|---|
| scan_id | string | Scan execution ID |
| url | string | Original URL |
| final_url | string/null | Final URL |
| status | string | completed / failed |
| status_code | integer/null | HTTP status code |
| headers | dict | HTTP response headers |
| cookies | list | Cookie information |
| redirect_count | integer | Redirect count |
| scanned_at | string | UTC timestamp |
| error | string/null | Error description |

Example:

```json
{
  "scan_id": "uuid",
  "url": "https://example.com",
  "final_url": "https://example.com/",
  "status": "completed",
  "status_code": 200,
  "headers": {},
  "cookies": [],
  "redirect_count": 0,
  "scanned_at": "2026-11-08T13:00:00+00:00",
  "error": null
}
```

## 4. Responsibilities

Scanner:
- Send HTTP GET requests.
- Enforce allowed host scope.
- Handle redirects and timeouts.
- Collect response headers and cookies.
- Return scan results.

Detection Rules:
- Analyze response headers and cookies.
- Detect missing security configurations.
- Generate findings.

Database:
- Store scan executions.
- Store findings and alerts.

Dashboard:
- Display scan history and findings.
- Allow users to manage alerts.

## 5. Usage Example

```python
from scanner import run_scan

report = run_scan(
    targets=["https://example.com"],
    allowed_hosts=["example.com"]
)

print(report)
```

## 6. Important Notes

- Only scan systems that are explicitly authorized.
- Redirect destinations must remain within allowed scope.
- Scanner collects data; it does not determine vulnerability severity.
