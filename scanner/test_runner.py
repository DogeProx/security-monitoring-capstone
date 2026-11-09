
from scanner.runner import run_scan


def fake_scan_url(url, allowed_hosts, timeout=5, max_redirects=5):
    if url == "https://example.com":
        return {
            "url": url,
            "status": "completed"
        }

    return {
        "url": url,
        "status": "failed"
    }


def test_all_urls_completed(monkeypatch):
    monkeypatch.setattr(
        "scanner.runner.scan_url",
        fake_scan_url
    )

    report = run_scan(
        targets=[
            "https://example.com",
            "https://example.org"
        ],
        allowed_hosts=[
            "example.com",
            "example.org"
        ]
    )

    assert report["status"] == "partial"
    assert report["summary"]["total"] == 2
    assert report["summary"]["completed"] == 1
    assert report["summary"]["failed"] == 1


def test_partial_scan_continues_after_failure(monkeypatch):
    monkeypatch.setattr(
        "scanner.runner.scan_url",
        fake_scan_url
    )

    progress_results = []

    def progress_callback(current, total, result):
        progress_results.append(result["url"])

    report = run_scan(
        targets=[
            "https://example.com",
            "https://google.com",
            "https://example.org"
        ],
        allowed_hosts=[
            "example.com",
            "example.org"
        ],
        progress_callback=progress_callback
    )

    assert report["status"] == "partial"
    assert len(report["results"]) == 3
    assert len(progress_results) == 3
    assert progress_results[-1] == "https://example.org"


def test_all_urls_failed(monkeypatch):
    def fake_failed_scan(url, allowed_hosts, timeout=5, max_redirects=5):
        return {
            "url": url,
            "status": "failed"
        }

    monkeypatch.setattr(
        "scanner.runner.scan_url",
        fake_failed_scan
    )

    report = run_scan(
        targets=[
            "https://google.com",
            "https://facebook.com"
        ],
        allowed_hosts=[
            "example.com"
        ]
    )

    assert report["status"] == "failed"
    assert report["summary"]["completed"] == 0
    assert report["summary"]["failed"] == 2


def test_progress_callback_called_for_every_url(monkeypatch):
    monkeypatch.setattr(
        "scanner.runner.scan_url",
        fake_scan_url
    )

    progress = []

    def callback(current, total, result):
        progress.append((current, total))

    run_scan(
        targets=[
            "https://example.com",
            "https://google.com",
            "https://example.org"
        ],
        allowed_hosts=[
            "example.com",
            "example.org"
        ],
        progress_callback=callback
    )

    assert progress == [
        (1, 3),
        (2, 3),
        (3, 3)
    ]
