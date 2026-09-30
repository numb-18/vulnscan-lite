import os
import pytest
from unittest.mock import MagicMock, patch

from scanner.headers import analyze_headers, CRITICAL_SECURITY_HEADERS
from scanner.cms_detector import detect_cms_and_tech, parse_semver, is_version_outdated
from scanner.scoring import calculate_grade, compile_scan_results
from scanner.pdf_generator import generate_pdf_report
from scanner.remediation import get_remediation_for_check

def test_semver_parser_and_outdated_check():
    assert parse_semver("5.4.1") == [5, 4, 1]
    assert parse_semver("6.4") == [6, 4, 0]
    assert is_version_outdated("5.4.1", "6.4.0") is True
    assert is_version_outdated("6.4.2", "6.4.0") is False
    assert is_version_outdated("10.1.0", "10.0.0") is False
    assert is_version_outdated("7.50", "10.0.0") is True

def test_cms_detector_with_wordpress_generator():
    html = """
    <!DOCTYPE html>
    <html>
      <head>
        <meta name="generator" content="WordPress 5.4.1" />
      </head>
      <body><h1>Sample Blog</h1></body>
    </html>
    """
    res = detect_cms_and_tech(html, {"server": "Apache/2.4"})
    assert res["detected_cms"] == "WordPress"
    assert res["cms_version"] == "5.4.1"
    assert res["is_outdated"] is True
    assert any(c["id"] == "cms_generator_exposure" and c["status"] == "WARNING" for c in res["checks"])
    assert any(c["id"] == "cms_version_outdated" and c["status"] == "FAILED" for c in res["checks"])

def test_cms_detector_clean_surface():
    html = "<html><head><title>Custom Web App</title></head><body>Hello world</body></html>"
    res = detect_cms_and_tech(html, {})
    assert res["detected_cms"] is None
    assert res["is_outdated"] is False
    assert any(c["id"] == "cms_platform_detected" and c["status"] == "PASSED" for c in res["checks"])

def test_headers_analysis_with_mock():
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.url = "https://secure-example.com"
    mock_resp.headers = {
        "Strict-Transport-Security": "max-age=31536000; includeSubDomains; preload",
        "Content-Security-Policy": "default-src 'self'",
        "X-Frame-Options": "DENY",
        "X-Content-Type-Options": "nosniff"
        # Referrer-Policy and Permissions-Policy missing
    }
    mock_resp.text = "<html>Secure Site</html>"

    mock_session = MagicMock()
    mock_session.get.return_value = mock_resp

    res = analyze_headers("https://secure-example.com", session=mock_session)
    assert res["is_https"] is True

    # Check that present headers passed
    hsts_check = next(c for c in res["checks"] if c["id"] == "header_strict_transport_security")
    assert hsts_check["status"] == "PASSED"
    assert hsts_check["points"] == 10

    csp_check = next(c for c in res["checks"] if c["id"] == "header_content_security_policy")
    assert csp_check["status"] == "PASSED"
    assert csp_check["points"] == 10

    # Missing header should fail and deduct points
    perm_check = next(c for c in res["checks"] if c["id"] == "header_permissions_policy")
    assert perm_check["status"] == "FAILED"
    assert perm_check["points"] == -10

def test_calculate_grade():
    assert calculate_grade(98)[0] == "A+"
    assert calculate_grade(92)[0] == "A"
    assert calculate_grade(85)[0] == "B"
    assert calculate_grade(75)[0] == "C"
    assert calculate_grade(65)[0] == "D"
    assert calculate_grade(45)[0] == "F"

def test_remediation_retrieval():
    rem = get_remediation_for_check("header_content_security_policy")
    assert "add_header Content-Security-Policy" in rem["nginx"]
    assert "Header always set Content-Security-Policy" in rem["apache"]

def test_pdf_report_generation(tmp_path):
    mock_report = {
        "target_url": "https://test.example.com",
        "score": 85,
        "grade": "B",
        "grade_label": "Good Posture (Minor Gaps)",
        "grade_color": "#60A5FA",
        "passed_count": 8,
        "failed_count": 2,
        "warning_count": 1,
        "total_checks": 11,
        "details": {
            "ssl_tls": {"valid": True, "tls_version": "TLSv1.3", "cipher": "AES256", "issuer": "Let's Encrypt", "days_until_expiry": 60, "expires_on": "2026-11-20"},
            "cms_tech": {"detected_cms": "WordPress", "cms_version": "6.4.2", "is_outdated": False, "tech_stack": ["WordPress v6.4.2", "Nginx"]}
        },
        "failed_checks": [
            {
                "id": "header_permissions_policy",
                "name": "Permissions-Policy",
                "status": "FAILED",
                "category": "Header Analysis",
                "message": "Permissions-Policy header is missing.",
                "risk": "Embedded iframes could access hardware APIs.",
                "remediation": get_remediation_for_check("header_permissions_policy")
            }
        ],
        "warning_checks": [],
        "passed_checks": [
            {"name": "Strict-Transport-Security", "category": "Header Analysis", "message": "Header is present: max-age=31536000"}
        ]
    }

    pdf_path = generate_pdf_report("test_scan_123", mock_report)
    assert os.path.exists(pdf_path)
    assert os.path.getsize(pdf_path) > 1000
