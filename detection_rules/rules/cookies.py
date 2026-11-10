from http.cookies import CookieError, SimpleCookie

from .headers import get_headers_lower


def check_httponly(response_data, session_cookie_names):
    cookies = response_data.get("cookies")
    if cookies is None:
        # Older callers may supply a single raw Set-Cookie header.
        parsed = SimpleCookie()
        try:
            parsed.load(get_headers_lower(response_data).get("set-cookie", ""))
        except CookieError:
            return []
        cookies = [
            {"name": name, "httponly": bool(morsel["httponly"])}
            for name, morsel in parsed.items()
        ]

    return [
        {
            "rule_id": "SEC-CKI-HTTPONLY",
            "severity": "High",
            "evidence": f"Cookie '{cookie['name']}' is missing HttpOnly flag.",
            "remediation": "Add HttpOnly flag to the session cookie creation logic.",
        }
        for cookie in cookies
        if cookie["name"] in session_cookie_names and not cookie["httponly"]
    ]
