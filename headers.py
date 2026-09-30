from typing import Dict, Any, List
import requests
from config import USER_AGENT, SCAN_TIMEOUT_SECONDS

CRITICAL_SECURITY_HEADERS = [
    {
        "name": "Content-Security-Policy",
        "header_key": "content-security-policy",
        "description": "Restricts resources (such as JavaScript, CSS, Images) that the browser is allowed to load.",
        "risk_if_missing": "High: Leaves site susceptible to Cross-Site Scripting (XSS), data injection, and clickjacking.",
        "category": "Header Analysis",
        "points": 10
    },
    {
        "name": "Strict-Transport-Security",
        "header_key": "strict-transport-security",
        "description": "Enforces secure (HTTP over SSL/TLS) connections to the server (HSTS).",
        "risk_if_missing": "High: Attackers on same network can perform SSL-stripping and Man-in-the-Middle (MITM) attacks.",
        "category": "Header Analysis",
        "points": 10
    },
    {
        "name": "X-Frame-Options",
        "header_key": "x-frame-options",
        "description": "Controls whether the site can be framed in an <iframe> or <embed>.",
        "risk_if_missing": "Medium: Allows malicious actors to perform Clickjacking attacks by framing your website.",
        "category": "Header Analysis",
        "points": 10
    },
    {
        "name": "X-Content-Type-Options",
        "header_key": "x-content-type-options",
        "description": "Prevents MIME type sniffing (must be set to 'nosniff').",
        "risk_if_missing": "Low: Browsers may execute non-executable files as scripts if MIME sniffing occurs.",
        "category": "Header Analysis",
        "points": 10
    },
    {
        "name": "Referrer-Policy",
        "header_key": "referrer-policy",
        "description": "Governs how much referrer information is sent with requests.",
        "risk_if_missing": "Low: Sensitive URLs containing tokens or session parameters might leak to 3rd-party sites.",
        "category": "Header Analysis",
        "points": 10
    },
    {
        "name": "Permissions-Policy",
        "header_key": "permissions-policy",
        "description": "Restricts browser features like camera, microphone, geolocation, and payment APIs.",
        "risk_if_missing": "Low: Embedded 3rd party iframes or compromised scripts might access sensitive browser APIs.",
        "category": "Header Analysis",
        "points": 10
    }
]

SENSITIVE_DISCLOSURE_HEADERS = [
    {"key": "server", "name": "Server", "risk": "Exposes underlying web server vendor and version."},
    {"key": "x-powered-by", "name": "X-Powered-By", "risk": "Exposes backend runtime/framework (e.g. PHP, Express, ASP.NET)."},
    {"key": "x-aspnet-version", "name": "X-AspNet-Version", "risk": "Exposes specific ASP.NET runtime version."},
    {"key": "x-generator", "name": "X-Generator", "risk": "Exposes CMS or publishing software version."}
]

def analyze_headers(target_url: str, session: requests.Session = None) -> Dict[str, Any]:
    """
    Performs HTTP request to the target URL, extracts headers, and evaluates security posture.
    Returns structured results with points added/deducted, passed and failed check items.
    """
    if session is None:
        session = requests.Session()
        
    headers_result = {
        "raw_headers": {},
        "status_code": None,
        "final_url": None,
        "is_https": False,
        "checks": [],
        "points_delta": 0,
        "error": None
    }
    
    try:
        req_headers = {
            "User-Agent": USER_AGENT,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
        }
        
        response = session.get(
            target_url,
            headers=req_headers,
            timeout=SCAN_TIMEOUT_SECONDS,
            allow_redirects=True,
            verify=False  # We do dedicated SSL analysis in ssl_tls module
        )
        
        headers_result["status_code"] = response.status_code
        headers_result["final_url"] = response.url
        headers_result["is_https"] = response.url.startswith("https://")
        
        # Lowercase mapping for case-insensitive lookup
        resp_headers = {k.lower(): v for k, v in response.headers.items()}
        headers_result["raw_headers"] = dict(response.headers)
        
        # HTTPS enforcement check
        if headers_result["is_https"]:
            headers_result["checks"].append({
                "id": "https_enforcement",
                "name": "HTTPS Protocol Enforced",
                "status": "PASSED",
                "points": 10,
                "message": f"Target communicates securely over HTTPS ({response.url}).",
                "category": "Transport Security"
            })
            headers_result["points_delta"] += 10
        else:
            headers_result["checks"].append({
                "id": "https_enforcement",
                "name": "HTTPS Protocol Enforced",
                "status": "FAILED",
                "points": -10,
                "message": "Target communicates over insecure HTTP without auto-redirecting to HTTPS.",
                "category": "Transport Security"
            })
            headers_result["points_delta"] -= 10
            
        # Security Headers Evaluation (+10 for present, -10 for missing)
        for h_def in CRITICAL_SECURITY_HEADERS:
            key = h_def["header_key"]
            val = resp_headers.get(key)
            
            if val:
                # Additional quality checks
                details = f"Header is present: '{val[:120]}...'" if len(val) > 120 else f"Header is present: '{val}'"
                
                # Special validation for HSTS
                if key == "strict-transport-security":
                    if "max-age" not in val.lower():
                        details += " (Warning: missing max-age directive)"
                
                # Special validation for X-Frame-Options
                if key == "x-frame-options":
                    val_upper = val.upper()
                    if "DENY" not in val_upper and "SAMEORIGIN" not in val_upper:
                        details += " (Warning: weak policy; recommend DENY or SAMEORIGIN)"
                
                headers_result["checks"].append({
                    "id": f"header_{key.replace('-', '_')}",
                    "name": h_def["name"],
                    "status": "PASSED",
                    "points": h_def["points"],
                    "value": val,
                    "message": details,
                    "description": h_def["description"],
                    "category": h_def["category"]
                })
                headers_result["points_delta"] += h_def["points"]
            else:
                headers_result["checks"].append({
                    "id": f"header_{key.replace('-', '_')}",
                    "name": h_def["name"],
                    "status": "FAILED",
                    "points": -h_def["points"],
                    "value": None,
                    "message": f"Security header '{h_def['name']}' is missing.",
                    "risk": h_def["risk_if_missing"],
                    "description": h_def["description"],
                    "category": h_def["category"]
                })
                headers_result["points_delta"] -= h_def["points"]
                
        # Information Disclosure Headers Evaluation
        disclosures_found = []
        for dis in SENSITIVE_DISCLOSURE_HEADERS:
            val = resp_headers.get(dis["key"])
            if val:
                disclosures_found.append(f"{dis['name']}: {val}")
                
        if disclosures_found:
            headers_result["checks"].append({
                "id": "info_disclosure_headers",
                "name": "Information Disclosure Headers",
                "status": "WARNING",
                "points": -5,
                "message": f"Server leaks technology details in headers: {'; '.join(disclosures_found)}",
                "risk": "Attackers can tailor exploit payloads targeting the specific web server or runtime version revealed.",
                "category": "Information Disclosure"
            })
            headers_result["points_delta"] -= 5
        else:
            headers_result["checks"].append({
                "id": "info_disclosure_headers",
                "name": "Information Disclosure Headers",
                "status": "PASSED",
                "points": 5,
                "message": "No server banner or runtime technology leakage detected in HTTP headers.",
                "category": "Information Disclosure"
            })
            headers_result["points_delta"] += 5
            
        headers_result["html_content"] = response.text
        
    except requests.RequestException as e:
        headers_result["error"] = str(e)
        headers_result["checks"].append({
            "id": "http_connection_failed",
            "name": "HTTP Reachability",
            "status": "FAILED",
            "points": -20,
            "message": f"Failed to establish HTTP connection: {str(e)}",
            "category": "Network"
        })
        headers_result["points_delta"] -= 20
        
    return headers_result
