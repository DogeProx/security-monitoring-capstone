from scanner.scope import is_in_scope

allowed_hosts = [
    "example.com",
    "test.example.com"
]

tests = [
    ("https://example.com", True),
    ("https://test.example.com", True),
    ("https://google.com", False),
    ("https://fakeexample.com", False),
    ("ftp://example.com", False),
    ("invalid-url", False)
]

for url, expected in tests:
    result = is_in_scope(url, allowed_hosts)

    status = "PASS" if result == expected else "FAIL"

    print(f"{status}: {url} -> {result}")