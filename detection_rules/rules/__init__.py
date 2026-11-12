from .headers import check_csp, check_xcto
from .cookies import check_httponly

def analyze_response(response_data, config=None, session_cookie_names=["session_id", "JSESSIONID"]):
    # Tuần 4: Thêm cấu hình bật/tắt quy tắc
    if config is None:
        config = {
            "SEC-HDR-CSP": True,
            "SEC-HDR-XCTO": True,
            "SEC-CKI-HTTPONLY": True
        }
        
    findings = []
    
    # Header rules
    if config.get("SEC-HDR-CSP"):
        csp_finding = check_csp(response_data)
        if csp_finding:
            findings.append(csp_finding)
            
    if config.get("SEC-HDR-XCTO"):
        xcto_finding = check_xcto(response_data)
        if xcto_finding:
            findings.append(xcto_finding)
            
    # Cookie rules
    if config.get("SEC-CKI-HTTPONLY"):
        cookie_findings = check_httponly(response_data, session_cookie_names)
        findings.extend(cookie_findings)
        
    return findings
