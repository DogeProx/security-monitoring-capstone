
from scanner.client import scan_url


ALLOWED_HOSTS = ["example.com"]

REQUIRED_FIELDS = {
    "url",
    "final_url",
    "status",
    "status_code",
    "headers",
    "cookies",
    "redirect_count",
    "scanned_at",
    "error"
}


def test_result_schema():
    success = scan_url(
        "https://example.com",
        ALLOWED_HOSTS
    )

    failed = scan_url(
        "https://google.com",
        ALLOWED_HOSTS
    )

    assert REQUIRED_FIELDS.issubset(success.keys())
    assert REQUIRED_FIELDS.issubset(failed.keys())

    assert success["status"] == "completed"
    assert failed["status"] == "failed"

    assert isinstance(success["headers"], dict)
    assert isinstance(failed["headers"], dict)

    assert isinstance(success["cookies"], list)
    assert isinstance(failed["cookies"], list)

    print("PASS: Success result schema")
    print("PASS: Failed result schema")
    print("PASS: All required fields exist")


if __name__ == "__main__":
    test_result_schema()
