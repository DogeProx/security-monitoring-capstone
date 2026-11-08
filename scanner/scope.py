from urllib.parse import urlparse


def normalize_host(url):
    try:
        parsed = urlparse(url)

        if parsed.scheme not in ("http", "https"):
            return None

        if not parsed.hostname:
            return None

        return parsed.hostname.lower().rstrip(".")

    except ValueError:
        return None


def is_in_scope(url, allowed_hosts):
    host = normalize_host(url)

    if host is None:
        return False

    allowed_hosts = {
        item.lower().rstrip(".")
        for item in allowed_hosts
    }

    return host in allowed_hosts