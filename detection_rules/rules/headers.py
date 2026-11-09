def get_headers_lower(response_data):
    raw_headers = response_data.get("headers", {})
    return {k.lower(): v for k, v in raw_headers.items()}

def check_csp(response_data):
    headers = get_headers_lower(response_data)
    content_type = headers.get("content-type", "").lower()
    
    if "text/html" in content_type:
        if "content-security-policy" not in headers:
            return {
                "rule_id": "SEC-HDR-CSP",
                "severity": "Medium",
                "evidence": "Missing Content-Security-Policy header in text/html response.",
                "remediation": "Configure server to return Content-Security-Policy header."
            }
    return None

def check_xcto(response_data):
    headers = get_headers_lower(response_data)
    xcto = headers.get("x-content-type-options", "").strip().lower()
    
    if xcto != "nosniff":
        evidence = f"Header value is '{xcto}', expected 'nosniff'." if xcto else "Missing X-Content-Type-Options header."
        return {
            "rule_id": "SEC-HDR-XCTO",
            "severity": "Low",
            "evidence": evidence,
            "remediation": "Configure server to return X-Content-Type-Options: nosniff."
        }
    return None
