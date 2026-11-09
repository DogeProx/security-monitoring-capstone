def get_headers_lower(response_data):
    raw_headers = response_data.get("headers", {})
    return {k.lower(): v for k, v in raw_headers.items()}

def check_httponly(response_data, session_cookie_names):
    findings = []
    headers = get_headers_lower(response_data)
    set_cookie = headers.get("set-cookie", "")
    
    if set_cookie:
        for cookie_name in session_cookie_names:
            if f"{cookie_name}=" in set_cookie:
                if "httponly" not in set_cookie.lower():
                    findings.append({
                        "rule_id": "SEC-CKI-HTTPONLY",
                        "severity": "High",
                        "evidence": f"Cookie '{cookie_name}' is missing HttpOnly flag.",
                        "remediation": "Add HttpOnly flag to the session cookie creation logic."
                    })
    return findings
