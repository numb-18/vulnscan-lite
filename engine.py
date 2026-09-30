import re
from urllib.parse import urlparse
from typing import Dict, Any, Callable, Optional

from .headers import analyze_headers
from .ssl_tls import inspect_ssl_tls
from .cms_detector import detect_cms_and_tech
from .scoring import compile_scan_results
from .pdf_generator import generate_pdf_report

def normalize_target_url(raw_url: str) -> str:
    """Ensures the target URL has a valid scheme and normalizes the format."""
    url = raw_url.strip()
    if not re.match(r"^https?://", url, re.I):
        url = f"https://{url}"
    parsed = urlparse(url)
    if not parsed.netloc:
        raise ValueError(f"Invalid URL structure: {raw_url}")
    return url

def run_scan_pipeline(
    scan_id: str,
    target_url: str,
    progress_callback: Optional[Callable[[str, str, int], None]] = None
) -> Dict[str, Any]:
    """
    Orchestrates the end-to-end passive vulnerability scan:
    1. URL normalization & validation
    2. HTTP Security Header Analysis (+10/-10 grading)
    3. SSL/TLS Certificate & Cipher Inspection
    4. CMS & Outdated Framework Detection
    5. Scoring aggregation & remediation generation
    6. PDF report compilation
    """
    def report_progress(status: str, stage: str, pct: int):
        if progress_callback:
            progress_callback(status, stage, pct)
            
    report_progress("running", "Validating target host and network reachability", 10)
    normalized_url = normalize_target_url(target_url)
    
    # Step 1: Headers Analysis
    report_progress("running", "Analyzing HTTP security headers and server exposure", 25)
    header_results = analyze_headers(normalized_url)
    
    # If initial HTTPS failed, try HTTP as fallback
    if header_results.get("error") and normalized_url.startswith("https://"):
        http_fallback = f"http://{urlparse(normalized_url).netloc}"
        report_progress("running", "Retrying via HTTP protocol...", 35)
        fallback_res = analyze_headers(http_fallback)
        if not fallback_res.get("error"):
            header_results = fallback_res
            normalized_url = http_fallback
            
    # Step 2: SSL/TLS Inspection
    report_progress("running", "Inspecting SSL/TLS certificate validity, expiry, and cipher suites", 55)
    ssl_results = inspect_ssl_tls(normalized_url)
    
    # Step 3: CMS & Tech Detection
    report_progress("running", "Detecting CMS signatures, meta generator tags, and outdated frameworks", 75)
    html_content = header_results.get("html_content", "")
    cms_results = detect_cms_and_tech(html_content, header_results.get("raw_headers", {}))
    
    # Step 4: Scoring & Grading
    report_progress("running", "Calculating security posture score and generating remediation plans", 88)
    compiled_report = compile_scan_results(
        target_url=target_url,
        normalized_url=normalized_url,
        header_res=header_results,
        ssl_res=ssl_results,
        cms_res=cms_results
    )
    
    # Step 5: PDF Generation
    report_progress("running", "Compiling executive PDF report card", 95)
    pdf_path = None
    try:
        pdf_path = generate_pdf_report(scan_id, compiled_report)
        compiled_report["pdf_path"] = pdf_path
    except Exception as e:
        compiled_report["pdf_error"] = str(e)
        
    return {
        "scan_id": scan_id,
        "score": compiled_report["score"],
        "grade": compiled_report["grade"],
        "report": compiled_report,
        "pdf_path": pdf_path
    }
