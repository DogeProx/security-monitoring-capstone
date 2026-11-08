
from scanner import run_scan, scan_url, is_in_scope


def test_public_interface():

    assert callable(run_scan)
    assert callable(scan_url)
    assert callable(is_in_scope)

    assert is_in_scope(
        "https://example.com",
        ["example.com"]
    )

    report = run_scan(
        targets=["https://example.com"],
        allowed_hosts=["example.com"]
    )

    assert report["summary"]["total"] == 1
    assert report["summary"]["completed"] == 1
    assert report["results"][0]["scan_id"] == report["scan_id"]

    print("PASS: Public imports")
    print("PASS: Scope interface")
    print("PASS: Runner interface")


if __name__ == "__main__":
    test_public_interface()
