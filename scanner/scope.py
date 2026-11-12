from urllib.parse import urlsplit


DEFAULT_PORTS = {"http": 80, "https": 443}


def _origin(url):
    if not isinstance(url, str) or "\\" in url or any(ord(char) <= 32 for char in url):
        return None

    try:
        parsed = urlsplit(url)
        if parsed.scheme not in DEFAULT_PORTS or not parsed.hostname:
            return None
        if parsed.username is not None or parsed.password is not None:
            return None

        port = parsed.port
        if port == 0:
            return None
        return (
            parsed.scheme,
            parsed.hostname.rstrip("."),
            DEFAULT_PORTS[parsed.scheme] if port is None else port,
        )
    except ValueError:
        return None


def normalize_host(url):
    origin = _origin(url)
    return origin[1] if origin else None


def is_in_scope(url, allowed_hosts):
    origin = _origin(url)
    if origin is None:
        return False

    scheme, host, port = origin
    for allowed in allowed_hosts:
        if _origin(allowed) == origin:
            return True
        if (
            isinstance(allowed, str)
            and allowed.lower().rstrip(".") == host
            and port == DEFAULT_PORTS[scheme]
        ):
            return True
    return False
