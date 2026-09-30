import re
from typing import Dict, Any, List, Optional
from bs4 import BeautifulSoup

# Minimum recommended / active LTS major versions for common CMS platforms
CMS_SECURITY_BASELINES = {
    "WordPress": {
        "min_version": "6.4.0",
        "advisory": "WordPress versions prior to 6.4 have multiple known vulnerabilities (e.g., CVE-2023-38000, remote code execution risks in legacy core plugins)."
    },
    "Drupal": {
        "min_version": "10.0.0",
        "advisory": "Drupal 7 and 8 have reached End-of-Life (EOL) and no longer receive public security patches (Drupalgeddon CVE-2018-7600 vulnerability risks)."
    },
    "Joomla": {
        "min_version": "5.0.0",
        "advisory": "Joomla versions below 4.4/5.0 have known privilege escalation and SQL injection CVEs."
    },
    "Ghost": {
        "min_version": "5.0.0",
        "advisory": "Ghost versions below 5.0 lack critical security features and recent patch updates."
    }
}

def parse_semver(version_str: str) -> List[int]:
    """Helper to convert version string into integer 3-tuples [major, minor, patch] for comparison."""
    numbers = re.findall(r"\d+", version_str)
    parts = [int(n) for n in numbers[:3]] if numbers else [0]
    while len(parts) < 3:
        parts.append(0)
    return parts

def is_version_outdated(detected_version: str, min_version: str) -> bool:
    detected_parts = parse_semver(detected_version)
    min_parts = parse_semver(min_version)
    return detected_parts < min_parts

def detect_cms_and_tech(html_content: str, raw_headers: Dict[str, str]) -> Dict[str, Any]:
    """
    Analyzes HTML content and HTTP headers to detect CMS, frameworks, and version signatures.
    Evaluates whether the site exposes its generator version or runs outdated software.
    """
    result = {
        "detected_cms": None,
        "cms_version": None,
        "is_outdated": False,
        "generator_tag": None,
        "tech_stack": [],
        "checks": [],
        "points_delta": 0
    }
    
    if not html_content:
        result["checks"].append({
            "id": "cms_content_analysis",
            "name": "CMS & Technology Signature",
            "status": "PASSED",
            "points": 5,
            "message": "No HTML response body available to fingerprint CMS.",
            "category": "Technology Fingerprinting"
        })
        result["points_delta"] += 5
        return result
        
    soup = BeautifulSoup(html_content, "html.parser")
    headers_lower = {k.lower(): v for k, v in raw_headers.items()}
    
    # 1. Generator Meta Tag
    gen_meta = soup.find("meta", attrs={"name": re.compile(r"^generator$", re.I)})
    generator_content = gen_meta.get("content", "").strip() if gen_meta else None
    result["generator_tag"] = generator_content
    
    # 2. Inspect Headers for Tech
    x_powered_by = headers_lower.get("x-powered-by", "")
    server_header = headers_lower.get("server", "")
    
    if x_powered_by:
        result["tech_stack"].append(f"Runtime: {x_powered_by}")
    if server_header:
        result["tech_stack"].append(f"Web Server: {server_header}")
        
    # 3. Detect CMS Platforms
    detected_platform = None
    detected_ver = None
    
    # Check Generator Tag first
    if generator_content:
        for cms in ["WordPress", "Drupal", "Joomla", "Ghost", "Shopify", "Wix", "Squarespace"]:
            if re.search(rf"\b{cms}\b", generator_content, re.I):
                detected_platform = cms
                ver_match = re.search(r"(\d+(\.\d+)+)", generator_content)
                if ver_match:
                    detected_ver = ver_match.group(1)
                break
                
    # Check HTML patterns if not identified yet
    if not detected_platform:
        html_str = str(soup)
        if "/wp-content/" in html_str or "/wp-includes/" in html_str:
            detected_platform = "WordPress"
            # Try to find version in script tags like ?ver=5.4.1
            ver_match = re.search(r"wp-(?:content|includes)[^\"']*\?ver=(\d+\.\d+(\.\d+)?)", html_str)
            if ver_match:
                detected_ver = ver_match.group(1)
        elif "Drupal.settings" in html_str or "/sites/default/files" in html_str:
            detected_platform = "Drupal"
        elif "/media/jui/" in html_str or "joomla" in html_str.lower():
            detected_platform = "Joomla"
        elif "cdn.shopify.com" in html_str:
            detected_platform = "Shopify"
        elif "wix.com" in html_str or "static.parastorage.com" in html_str:
            detected_platform = "Wix"
            
    result["detected_cms"] = detected_platform
    result["cms_version"] = detected_ver
    
    if detected_platform:
        result["tech_stack"].append(f"CMS: {detected_platform}" + (f" v{detected_ver}" if detected_ver else ""))
        
    # Evaluate Security Posture for CMS Detection
    # Check A: Exposing meta generator tag
    if generator_content:
        result["checks"].append({
            "id": "cms_generator_exposure",
            "name": "CMS Generator Tag Exposure",
            "status": "WARNING",
            "points": -5,
            "message": f"Site publicly reveals CMS via <meta name=\"generator\" content=\"{generator_content}\">.",
            "risk": "Publicly visible version tags allow automated scanners to target your exact software release for known exploits.",
            "category": "Technology Fingerprinting"
        })
        result["points_delta"] -= 5
    else:
        result["checks"].append({
            "id": "cms_generator_exposure",
            "name": "CMS Generator Tag Concealed",
            "status": "PASSED",
            "points": 5,
            "message": "HTML generator meta tags are hidden or disabled.",
            "category": "Technology Fingerprinting"
        })
        result["points_delta"] += 5
        
    # Check B: Outdated CMS Check
    if detected_platform in CMS_SECURITY_BASELINES:
        baseline = CMS_SECURITY_BASELINES[detected_platform]
        min_ver = baseline["min_version"]
        
        if detected_ver:
            if is_version_outdated(detected_ver, min_ver):
                result["is_outdated"] = True
                result["checks"].append({
                    "id": "cms_version_outdated",
                    "name": f"Outdated {detected_platform} Core Version",
                    "status": "FAILED",
                    "points": -15,
                    "message": f"Detected {detected_platform} version {detected_ver}, which is older than recommended secure baseline ({min_ver}).",
                    "risk": baseline["advisory"],
                    "category": "Technology Fingerprinting"
                })
                result["points_delta"] -= 15
            else:
                result["checks"].append({
                    "id": "cms_version_outdated",
                    "name": f"Current {detected_platform} Version",
                    "status": "PASSED",
                    "points": 10,
                    "message": f"{detected_platform} version {detected_ver} satisfies modern security baseline.",
                    "category": "Technology Fingerprinting"
                })
                result["points_delta"] += 10
        else:
            result["checks"].append({
                "id": "cms_version_outdated",
                "name": f"{detected_platform} Detected (Version Concealed)",
                "status": "PASSED",
                "points": 5,
                "message": f"{detected_platform} detected, but exact version number is protected from public disclosure.",
                "category": "Technology Fingerprinting"
            })
            result["points_delta"] += 5
    elif detected_platform:
        result["checks"].append({
            "id": "cms_platform_detected",
            "name": "Managed CMS Platform Detected",
            "status": "PASSED",
            "points": 5,
            "message": f"Running on managed service platform ({detected_platform}).",
            "category": "Technology Fingerprinting"
        })
        result["points_delta"] += 5
    else:
        result["checks"].append({
            "id": "cms_platform_detected",
            "name": "Clean Application Surface",
            "status": "PASSED",
            "points": 10,
            "message": "No legacy CMS fingerprints detected. Custom or headless architecture.",
            "category": "Technology Fingerprinting"
        })
        result["points_delta"] += 10
        
    return result
