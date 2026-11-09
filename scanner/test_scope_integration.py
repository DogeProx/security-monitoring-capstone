
from scanner.client import scan_url
import json

allowed_hosts = [
    "example.com"
]

tests = [
    "https://example.com",
    "https://google.com"
]

for url in tests:
    print(f"\nTesting: {url}")

    result = scan_url(
        url=url,
        allowed_hosts=allowed_hosts
    )

    print(json.dumps(result, indent=4, ensure_ascii=False))
