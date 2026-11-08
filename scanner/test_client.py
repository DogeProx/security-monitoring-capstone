
from scanner.client import scan_url
import json

allowed_hosts = [
    "example.com"
]

url = "https://example.com"

result = scan_url(
    url=url,
    allowed_hosts=allowed_hosts
)

print(json.dumps(result, indent=4, ensure_ascii=False))
