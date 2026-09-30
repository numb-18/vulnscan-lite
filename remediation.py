from typing import Dict, Any

REMEDIATION_DATABASE: Dict[str, Dict[str, Any]] = {
    "header_content_security_policy": {
        "title": "Configure Content-Security-Policy (CSP)",
        "summary": "CSP prevents Cross-Site Scripting (XSS), data injection, and rogue script execution by defining approved sources of content.",
        "nginx": 'add_header Content-Security-Policy "default-src \'self\'; script-src \'self\' https://trustedscripts.com; style-src \'self\' \'unsafe-inline\'; img-src \'self\' data:;" always;',
        "apache": 'Header always set Content-Security-Policy "default-src \'self\'; script-src \'self\'; style-src \'self\' \'unsafe-inline\'; img-src \'self\' data:;"',
        "caddy": 'header Content-Security-Policy "default-src \'self\'; script-src \'self\'; style-src \'self\'; img-src \'self\' data:;"',
        "express": 'const helmet = require("helmet");\napp.use(helmet.contentSecurityPolicy());',
        "documentation": "https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP"
    },
    "header_strict_transport_security": {
        "title": "Enable HTTP Strict Transport Security (HSTS)",
        "summary": "HSTS forces user browsers to only communicate over encrypted HTTPS connections, protecting against SSL-stripping MITM attacks.",
        "nginx": 'add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;',
        "apache": 'Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"',
        "caddy": 'header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"',
        "express": 'const helmet = require("helmet");\napp.use(helmet.hsts({ maxAge: 31536000, includeSubDomains: true, preload: true }));',
        "documentation": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security"
    },
    "header_x_frame_options": {
        "title": "Add X-Frame-Options Header",
        "summary": "Protects against clickjacking attacks by blocking unauthorized framing of your site in iframes.",
        "nginx": 'add_header X-Frame-Options "SAMEORIGIN" always;',
        "apache": 'Header always set X-Frame-Options "SAMEORIGIN"',
        "caddy": 'header X-Frame-Options "SAMEORIGIN"',
        "express": 'const helmet = require("helmet");\napp.use(helmet.frameguard({ action: "sameorigin" }));',
        "documentation": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options"
    },
    "header_x_content_type_options": {
        "title": "Prevent MIME Type Sniffing",
        "summary": "Instructs browsers to strictly honor declared Content-Type, preventing script execution from image or style uploads.",
        "nginx": 'add_header X-Content-Type-Options "nosniff" always;',
        "apache": 'Header always set X-Content-Type-Options "nosniff"',
        "caddy": 'header X-Content-Type-Options "nosniff"',
        "express": 'const helmet = require("helmet");\napp.use(helmet.noSniff());',
        "documentation": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options"
    },
    "header_referrer_policy": {
        "title": "Configure Referrer-Policy",
        "summary": "Limits sensitive URL parameters (passwords, tokens, user IDs) from leaking to third-party domains in Referer headers.",
        "nginx": 'add_header Referrer-Policy "strict-origin-when-cross-origin" always;',
        "apache": 'Header always set Referrer-Policy "strict-origin-when-cross-origin"',
        "caddy": 'header Referrer-Policy "strict-origin-when-cross-origin"',
        "express": 'const helmet = require("helmet");\napp.use(helmet.referrerPolicy({ policy: "strict-origin-when-cross-origin" }));',
        "documentation": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy"
    },
    "header_permissions_policy": {
        "title": "Implement Permissions-Policy",
        "summary": "Controls which browser features and hardware APIs (camera, microphone, geolocation, usb) are allowed to execute.",
        "nginx": 'add_header Permissions-Policy "camera=(), microphone=(), geolocation=(), payment=()" always;',
        "apache": 'Header always set Permissions-Policy "camera=(), microphone=(), geolocation=(), payment=()"',
        "caddy": 'header Permissions-Policy "camera=(), microphone=(), geolocation=(), payment=()"',
        "express": 'app.use((req, res, next) => {\n  res.setHeader("Permissions-Policy", "camera=(), microphone=(), geolocation=()");\n  next();\n});',
        "documentation": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Permissions-Policy"
    },
    "info_disclosure_headers": {
        "title": "Suppress Server and Technology Banners",
        "summary": "Hides detailed server versions (e.g., Apache/2.4.41, PHP 7.4.3) to prevent targeted automated exploit scanning.",
        "nginx": '# In /etc/nginx/nginx.conf http block:\nserver_tokens off;\nmore_clear_headers Server; # requires headers-more module',
        "apache": '# In httpd.conf or apache2.conf:\nServerTokens Prod\nServerSignature Off',
        "caddy": 'header -Server',
        "express": 'app.disable("x-powered-by");',
        "documentation": "https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html"
    },
    "https_enforcement": {
        "title": "Enforce HTTPS Redirection",
        "summary": "Automatically redirect all insecure HTTP traffic to HTTPS to ensure encrypted communication across all connections.",
        "nginx": 'server {\n    listen 80;\n    server_name yourdomain.com www.yourdomain.com;\n    return 301 https://$host$request_uri;\n}',
        "apache": 'RewriteEngine On\nRewriteCond %{HTTPS} off\nRewriteRule ^(.*)$ https://%{HTTP_HOST}%{REQUEST_URI} [L,R=301]',
        "caddy": '# Caddy automatically enforces HTTPS by default on port 80/443.',
        "express": 'app.use((req, res, next) => {\n  if (!req.secure && req.get("x-forwarded-proto") !== "https") {\n    return res.redirect(301, "https://" + req.headers.host + req.url);\n  }\n  next();\n});',
        "documentation": "https://letsencrypt.org/getting-started/"
    },
    "ssl_certificate_valid": {
        "title": "Install a Trusted SSL/TLS Certificate",
        "summary": "Ensure an active, trusted certificate issued by a recognized Certificate Authority (like Let\'s Encrypt) is installed.",
        "nginx": '# Install free SSL via Certbot:\n# certbot --nginx -d yourdomain.com',
        "apache": '# Install free SSL via Certbot:\n# certbot --apache -d yourdomain.com',
        "caddy": '# Caddy automatically issues and renews Let\'s Encrypt / ZeroSSL certificates out-of-the-box.',
        "express": '// Run behind a reverse proxy (e.g. Nginx or Cloudflare) configured with TLS.',
        "documentation": "https://certbot.eff.org/"
    },
    "ssl_certificate_expiration": {
        "title": "Renew SSL/TLS Certificate",
        "summary": "The SSL certificate is nearing expiration or has already expired. Renew immediately to prevent browser warning screens.",
        "nginx": '# Trigger Certbot renewal:\nsudo certbot renew --force-renewal\nsudo systemctl reload nginx',
        "apache": '# Trigger Certbot renewal:\nsudo certbot renew --force-renewal\nsudo systemctl reload apache2',
        "caddy": '# Caddy automatically renews certificates before expiration.',
        "express": '# Renew SSL cert on reverse proxy or load balancer.',
        "documentation": "https://letsencrypt.org/docs/automated-renewals/"
    },
    "ssl_tls_version": {
        "title": "Disable Insecure TLS Versions (TLS 1.0 & 1.1)",
        "summary": "Enforce TLSv1.2 and TLSv1.3 protocols only. Deprecated protocols are vulnerable to POODLE, BEAST, and Sweet32 attacks.",
        "nginx": 'ssl_protocols TLSv1.2 TLSv1.3;\nssl_prefer_server_ciphers off;',
        "apache": 'SSLProtocol -all +TLSv1.2 +TLSv1.3',
        "caddy": 'tls {\n    protocols tls1.2 tls1.3\n}',
        "express": '# Configure TLS protocol minimum on your reverse proxy.',
        "documentation": "https://ssl-config.mozilla.org/"
    },
    "ssl_cipher_strength": {
        "title": "Harden TLS Cipher Suites",
        "summary": "Configure strong cipher suites (e.g., ECDHE-ECDSA-AES128-GCM-SHA256, ECDHE-RSA-AES256-GCM-SHA384) and disable weak ciphers.",
        "nginx": 'ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384;',
        "apache": 'SSLCipherSuite ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384',
        "caddy": 'tls {\n    ciphers TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256\n}',
        "express": '# Configure ciphers at reverse proxy level.',
        "documentation": "https://ssl-config.mozilla.org/"
    },
    "cms_generator_exposure": {
        "title": "Remove Generator Meta Tags",
        "summary": "Hide `<meta name=\"generator\" ...>` tags from your HTML templates so attackers cannot scrape your CMS version.",
        "nginx": '# In WordPress functions.php:\nremove_action(\'wp_head\', \'wp_generator\');',
        "apache": '# In WordPress functions.php:\nremove_action(\'wp_head\', \'wp_generator\');',
        "caddy": '# Remove from application template headers.',
        "express": 'app.disable("x-powered-by");',
        "documentation": "https://developer.wordpress.org/reference/functions/wp_generator/"
    },
    "cms_version_outdated": {
        "title": "Update CMS to Latest Patched Release",
        "summary": "Upgrade your Content Management System (WordPress, Drupal, Joomla) to the current supported LTS release immediately.",
        "nginx": '# For WordPress:\nwp core update\nwp plugin update --all\nwp theme update --all',
        "apache": '# For WordPress:\nwp core update\nwp plugin update --all',
        "caddy": '# Update CMS via application admin dashboard or CLI.',
        "express": 'npm audit fix',
        "documentation": "https://wordpress.org/download/"
    }
}

def get_remediation_for_check(check_id: str) -> Dict[str, Any]:
    """Returns remediation advice and configuration snippets for a given check ID."""
    return REMEDIATION_DATABASE.get(check_id, {
        "title": "General Security Hardening",
        "summary": "Review your application configuration against OWASP Top 10 guidelines.",
        "nginx": "# Review server block security headers and access controls.",
        "apache": "# Review .htaccess or virtual host configuration.",
        "caddy": "# Review Caddyfile directives.",
        "express": "# Use security middleware such as helmet.",
        "documentation": "https://owasp.org/www-project-top-ten/"
    })
