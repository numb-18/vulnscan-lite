import socket
import ssl
from datetime import datetime, timezone
from urllib.parse import urlparse
from typing import Dict, Any, Optional

def inspect_ssl_tls(target_url: str, port: int = 443, timeout: int = 10) -> Dict[str, Any]:
    """
    Uses Python's standard ssl & socket libraries to connect to the target host and inspect:
    - Certificate validity and expiration date
    - Issuer CA details and Subject Common Names
    - Negotiated TLS protocol version (TLSv1.2, TLSv1.3)
    - Cipher suite name and bit strength
    - Self-signed certificate checks
    """
    parsed = urlparse(target_url if "://" in target_url else f"https://{target_url}")
    hostname = parsed.hostname or target_url
    if parsed.port:
        port = parsed.port
        
    result = {
        "hostname": hostname,
        "port": port,
        "is_valid": False,
        "issuer": None,
        "subject": None,
        "san": [],
        "issued_on": None,
        "expires_on": None,
        "days_until_expiry": None,
        "tls_version": None,
        "cipher": None,
        "cipher_bits": None,
        "is_self_signed": False,
        "checks": [],
        "points_delta": 0,
        "error": None
    }
    
    # Non-HTTPS URLs check
    if parsed.scheme == "http" and parsed.port is None and not target_url.startswith("https://"):
        # We still attempt SSL connection to port 443 to see if SSL is supported
        port = 443
        
    context = ssl.create_default_context()
    
    try:
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                cipher = ssock.cipher()
                tls_version = ssock.version()
                
                result["is_valid"] = True
                result["tls_version"] = tls_version
                if cipher:
                    result["cipher"] = cipher[0]
                    result["cipher_bits"] = cipher[2]
                
                # Subject extraction
                subject_dict = {}
                for rdn in cert.get("subject", ()):
                    for key, val in rdn:
                        subject_dict[key] = val
                result["subject"] = subject_dict.get("commonName") or str(subject_dict)
                
                # Issuer extraction
                issuer_dict = {}
                for rdn in cert.get("issuer", ()):
                    for key, val in rdn:
                        issuer_dict[key] = val
                result["issuer"] = issuer_dict.get("organizationName") or issuer_dict.get("commonName") or str(issuer_dict)
                
                # SAN (Subject Alternative Names)
                sans = [item[1] for item in cert.get("subjectAltName", ()) if item[0] == "DNS"]
                result["san"] = sans
                
                # Expiration parsing
                # Example format: 'May  5 23:59:59 2026 GMT'
                not_before_str = cert.get("notBefore")
                not_after_str = cert.get("notAfter")
                
                if not_after_str:
                    try:
                        expires_dt = datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                        result["expires_on"] = expires_dt.isoformat()
                        now_utc = datetime.now(timezone.utc)
                        delta = expires_dt - now_utc
                        result["days_until_expiry"] = delta.days
                    except Exception:
                        result["expires_on"] = not_after_str
                        
                if not_before_str:
                    try:
                        issued_dt = datetime.strptime(not_before_str, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                        result["issued_on"] = issued_dt.isoformat()
                    except Exception:
                        result["issued_on"] = not_before_str
                        
                # Self signed test
                result["is_self_signed"] = (result["subject"] == result["issuer"])
                
                # Evaluate SSL checks and grading
                # Check 1: Certificate Validity & Trust
                result["checks"].append({
                    "id": "ssl_certificate_valid",
                    "name": "SSL/TLS Certificate Validity",
                    "status": "PASSED",
                    "points": 10,
                    "message": f"Valid certificate issued by trusted CA ({result['issuer']}).",
                    "category": "SSL/TLS Security"
                })
                result["points_delta"] += 10
                
                # Check 2: Expiration Timeline
                if result["days_until_expiry"] is not None:
                    if result["days_until_expiry"] <= 0:
                        result["checks"].append({
                            "id": "ssl_certificate_expiration",
                            "name": "Certificate Expiration Date",
                            "status": "FAILED",
                            "points": -15,
                            "message": f"SSL certificate has expired! Expired on {result['expires_on']}.",
                            "risk": "Critical: Browsers will display full-page security warnings blocking users.",
                            "category": "SSL/TLS Security"
                        })
                        result["points_delta"] -= 15
                    elif result["days_until_expiry"] < 15:
                        result["checks"].append({
                            "id": "ssl_certificate_expiration",
                            "name": "Certificate Expiration Date",
                            "status": "WARNING",
                            "points": -5,
                            "message": f"SSL certificate expires in {result['days_until_expiry']} days. Immediate renewal required.",
                            "category": "SSL/TLS Security"
                        })
                        result["points_delta"] -= 5
                    elif result["days_until_expiry"] < 30:
                        result["checks"].append({
                            "id": "ssl_certificate_expiration",
                            "name": "Certificate Expiration Date",
                            "status": "WARNING",
                            "points": 0,
                            "message": f"SSL certificate will expire in {result['days_until_expiry']} days. Plan renewal soon.",
                            "category": "SSL/TLS Security"
                        })
                    else:
                        result["checks"].append({
                            "id": "ssl_certificate_expiration",
                            "name": "Certificate Expiration Date",
                            "status": "PASSED",
                            "points": 10,
                            "message": f"Certificate is active with {result['days_until_expiry']} days remaining until expiration.",
                            "category": "SSL/TLS Security"
                        })
                        result["points_delta"] += 10
                        
                # Check 3: TLS Protocol Version
                if tls_version in ("TLSv1.3", "TLSv1.2"):
                    result["checks"].append({
                        "id": "ssl_tls_version",
                        "name": "Modern TLS Protocol Version",
                        "status": "PASSED",
                        "points": 10,
                        "message": f"Server supports secure protocol {tls_version}.",
                        "category": "SSL/TLS Security"
                    })
                    result["points_delta"] += 10
                else:
                    result["checks"].append({
                        "id": "ssl_tls_version",
                        "name": "Modern TLS Protocol Version",
                        "status": "FAILED",
                        "points": -15,
                        "message": f"Legacy or deprecated protocol detected: {tls_version}. Must use TLSv1.2 or TLSv1.3.",
                        "risk": "Deprecated protocols (TLSv1.0/1.1, SSLv3) have known cryptographic vulnerabilities (POODLE, BEAST).",
                        "category": "SSL/TLS Security"
                    })
                    result["points_delta"] -= 15
                    
                # Check 4: Cipher Suite Strength
                bits = result["cipher_bits"] or 0
                cipher_name = result["cipher"] or "Unknown"
                if bits >= 128:
                    result["checks"].append({
                        "id": "ssl_cipher_strength",
                        "name": "Cipher Suite Bit Strength",
                        "status": "PASSED",
                        "points": 10,
                        "message": f"Strong encryption cipher negotiated: {cipher_name} ({bits}-bit keys).",
                        "category": "SSL/TLS Security"
                    })
                    result["points_delta"] += 10
                else:
                    result["checks"].append({
                        "id": "ssl_cipher_strength",
                        "name": "Cipher Suite Bit Strength",
                        "status": "FAILED",
                        "points": -10,
                        "message": f"Weak or export-grade cipher detected: {cipher_name} ({bits}-bit).",
                        "risk": "Weak ciphers (<128-bit) can be decrypted by attackers through brute-force computation.",
                        "category": "SSL/TLS Security"
                    })
                    result["points_delta"] -= 10
                    
    except ssl.SSLCertVerificationError as e:
        result["error"] = f"SSL Verification Error: {e.verify_message}"
        result["checks"].append({
            "id": "ssl_certificate_valid",
            "name": "SSL/TLS Certificate Validity",
            "status": "FAILED",
            "points": -20,
            "message": f"SSL certificate verification failed: {e.verify_message}",
            "risk": "Certificate is invalid, self-signed, or untrusted. Users will receive security warnings.",
            "category": "SSL/TLS Security"
        })
        result["points_delta"] -= 20
    except (socket.timeout, socket.gaierror, ConnectionRefusedError, ssl.SSLError) as e:
        result["error"] = f"SSL Connection Error: {str(e)}"
        result["checks"].append({
            "id": "ssl_certificate_valid",
            "name": "SSL/TLS Certificate Validity",
            "status": "FAILED",
            "points": -20,
            "message": f"Could not establish secure SSL/TLS connection: {str(e)}",
            "risk": "Port 443 is closed or SSL handshake failed.",
            "category": "SSL/TLS Security"
        })
        result["points_delta"] -= 20
        
    return result
