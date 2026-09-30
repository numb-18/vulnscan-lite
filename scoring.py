from typing import Dict, Any, List, Tuple
from .remediation import get_remediation_for_check

def calculate_grade(score: int) -> Tuple[str, str, str]:
    """
    Returns (grade, label, badge_color).
    """
    if score >= 95:
        return "A+", "Exemplary Security Posture", "#10B981"  # Emerald
    elif score >= 90:
        return "A", "Strong Security Posture", "#34D399"   # Green
    elif score >= 80:
        return "B", "Good Posture (Minor Gaps)", "#60A5FA"  # Blue
    elif score >= 70:
        return "C", "Fair Posture (Multiple Issues)", "#FBBF24" # Amber
    elif score >= 60:
        return "D", "Weak Posture (Elevated Risk)", "#F97316" # Orange
    else:
        return "F", "Critical Deficiencies", "#EF4444"      # Red

def compile_scan_results(
    target_url: str,
    normalized_url: str,
    header_res: Dict[str, Any],
    ssl_res: Dict[str, Any],
    cms_res: Dict[str, Any]
) -> Dict[str, Any]:
    """
    Aggregates checks from all three modules, applies the scoring rules,
    classifies Passed/Failed/Warnings, attaches remediation advice, and assigns the letter grade.
    """
    all_checks = []
    
    # Collect all checks
    all_checks.extend(header_res.get("checks", []))
    all_checks.extend(ssl_res.get("checks", []))
    all_checks.extend(cms_res.get("checks", []))
    
    passed_checks = []
    failed_checks = []
    warning_checks = []
    
    # Start with baseline of 60, add points from passes, deduct points from failures
    # Maximum obtainable raw score: around 80 points above baseline.
    raw_points = 50
    for c in all_checks:
        raw_points += c.get("points", 0)
        
    final_score = max(0, min(100, raw_points))
    grade, grade_label, grade_color = calculate_grade(final_score)
    
    for check in all_checks:
        status = check.get("status", "FAILED")
        cid = check.get("id", "")
        
        # Attach remediation data for failed or warning checks
        if status in ("FAILED", "WARNING"):
            check["remediation"] = get_remediation_for_check(cid)
            if status == "FAILED":
                failed_checks.append(check)
            else:
                warning_checks.append(check)
        else:
            passed_checks.append(check)
            
    summary = {
        "target_url": target_url,
        "normalized_url": normalized_url,
        "score": final_score,
        "grade": grade,
        "grade_label": grade_label,
        "grade_color": grade_color,
        "total_checks": len(all_checks),
        "passed_count": len(passed_checks),
        "failed_count": len(failed_checks),
        "warning_count": len(warning_checks),
        "passed_checks": passed_checks,
        "failed_checks": failed_checks,
        "warning_checks": warning_checks,
        "all_checks": all_checks,
        "details": {
            "is_https": header_res.get("is_https", False),
            "status_code": header_res.get("status_code"),
            "ssl_tls": {
                "valid": ssl_res.get("is_valid", False),
                "issuer": ssl_res.get("issuer"),
                "subject": ssl_res.get("subject"),
                "tls_version": ssl_res.get("tls_version"),
                "cipher": ssl_res.get("cipher"),
                "days_until_expiry": ssl_res.get("days_until_expiry"),
                "expires_on": ssl_res.get("expires_on")
            },
            "cms_tech": {
                "detected_cms": cms_res.get("detected_cms"),
                "cms_version": cms_res.get("cms_version"),
                "is_outdated": cms_res.get("is_outdated", False),
                "generator_tag": cms_res.get("generator_tag"),
                "tech_stack": cms_res.get("tech_stack", [])
            }
        }
    }
    
    return summary
