from .headers import check_csp, check_xcto
from .cookies import check_httponly

def analyze_response(response_data, session_cookie_names=("session_id", "JSESSIONID")):
    findings = []
    
    # Header rules
    csp_finding = check_csp(response_data)
    if csp_finding:
        findings.append(csp_finding)
        
    xcto_finding = check_xcto(response_data)
    if xcto_finding:
        findings.append(xcto_finding)
        
    # Cookie rules
    cookie_findings = check_httponly(response_data, session_cookie_names)
    findings.extend(cookie_findings)
    
    return findings
