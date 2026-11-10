
import requests
from urllib.parse import urljoin
from datetime import datetime, timezone

from scanner.scope import is_in_scope


def scan_url(url, allowed_hosts, timeout=5, max_redirects=5):
    """
    Send HTTP GET requests and collect response information.
    Only requests URLs within the allowed scope.
    """

    
    def failed(error, final_url=None, redirect_count=0):
        return {
            "url": url,
            "final_url": final_url,
            "status": "failed",
            "status_code": None,
            "headers": {},
            "cookies": [],
            "redirect_count": redirect_count,
            "scanned_at": datetime.now(timezone.utc).isoformat(),
            "error": error
        }


    allowed_hosts = tuple(allowed_hosts)
    if not is_in_scope(url, allowed_hosts):
        return failed("URL is outside allowed scope")

    current_url = url
    redirect_count = 0

    try:
        with requests.Session() as session:
            session.headers.update({
                "User-Agent": "GroupWebSecurityScanner/1.0"
            })

            while True:

                # Check scope before every request
                if not is_in_scope(current_url, allowed_hosts):
                    return failed(
                        "Redirect target is outside allowed scope",
                        current_url,
                        redirect_count
                    )

                response = session.get(
                    current_url,
                    timeout=timeout,
                    allow_redirects=False,
                    stream=True
                )

                try:
                    # Handle redirects manually
                    if response.status_code in (301, 302, 303, 307, 308):
                        location = response.headers.get("Location")

                        if location:
                            next_url = urljoin(response.url, location)

                            if not is_in_scope(next_url, allowed_hosts):
                                return failed(
                                    "Redirect target is outside allowed scope",
                                    next_url,
                                    redirect_count
                                )

                            if redirect_count >= max_redirects:
                                return failed(
                                    "Too many redirects",
                                    current_url,
                                    redirect_count
                                )

                            current_url = next_url
                            redirect_count += 1
                            continue

                    # Collect cookies
                    cookies = []

                    for cookie in response.cookies:
                        cookie_options = cookie._rest

                        cookies.append({
                            "name": cookie.name,
                            "httponly": any(
                                key.lower() == "httponly"
                                for key in cookie_options
                            ),
                            "secure": cookie.secure,
                            "samesite": next(
                                (
                                    value for key, value
                                    in cookie_options.items()
                                    if key.lower() == "samesite"
                                ),
                                None
                            )
                        })

                    return {
                        "url": url,
                        "final_url": response.url,
                        "status": "completed",
                        "status_code": response.status_code,
                        "headers": {
                            name: value for name, value in response.headers.items()
                            if name.lower() not in {"set-cookie", "set-cookie2"}
                        },
                        "cookies": cookies,
                        "redirect_count": redirect_count,
                        "scanned_at": datetime.now(
                            timezone.utc
                        ).isoformat(),
                        "error": None
                    }

                finally:
                    response.close()

    except requests.exceptions.Timeout:
        return failed("Request timeout", current_url, redirect_count)

    except requests.exceptions.TooManyRedirects:
        return failed("Too many redirects", current_url, redirect_count)

    except requests.exceptions.RequestException as e:
        return failed(str(e), current_url, redirect_count)
