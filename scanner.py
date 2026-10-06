import requests
import socket
import ssl
import time
import dns.resolver

from datetime import datetime, timezone
from urllib.parse import urlparse

from port_scanner import scan_ports
from recon import run_recon
from vulnerability_scanner import run_vulnerability_scan


HEADERS = {
    "User-Agent": "WebGuard/4.0 Security Scanner"
}


SECURITY_HEADERS = [
    "Content-Security-Policy",
    "Strict-Transport-Security",
    "X-Content-Type-Options",
    "X-Frame-Options",
    "Referrer-Policy",
    "Permissions-Policy"
]


def normalize_url(url):

    url = url.strip()

    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    return url


def get_ssl_info(hostname):

    result = {
        "status": "Unknown",
        "tls_version": None,
        "cipher": None,
        "issuer": None,
        "subject": None,
        "expires": None,
        "days_remaining": None,
        "error": None
    }

    try:

        context = ssl.create_default_context()

        with socket.create_connection(
            (hostname, 443),
            timeout=5
        ) as sock:

            with context.wrap_socket(
                sock,
                server_hostname=hostname
            ) as secure_socket:

                certificate = secure_socket.getpeercert()

                result["tls_version"] = (
                    secure_socket.version()
                )

                cipher = secure_socket.cipher()

                if cipher:
                    result["cipher"] = cipher[0]

                issuer = certificate.get("issuer")

                if issuer:
                    result["issuer"] = " / ".join(
                        value
                        for group in issuer
                        for key, value in group
                    )

                subject = certificate.get("subject")

                if subject:
                    result["subject"] = " / ".join(
                        value
                        for group in subject
                        for key, value in group
                    )

                expires_raw = certificate.get(
                    "notAfter"
                )

                if expires_raw:

                    expires_dt = datetime.strptime(
                        expires_raw,
                        "%b %d %H:%M:%S %Y %Z"
                    ).replace(
                        tzinfo=timezone.utc
                    )

                    now = datetime.now(timezone.utc)

                    days_remaining = (
                        expires_dt - now
                    ).days

                    result["expires"] = (
                        expires_dt.strftime(
                            "%Y-%m-%d %H:%M:%S UTC"
                        )
                    )

                    result["days_remaining"] = (
                        days_remaining
                    )

                    if days_remaining >= 0:
                        result["status"] = "Valid"
                    else:
                        result["status"] = "Expired"

    except Exception as error:

        result["status"] = "Unavailable"
        result["error"] = str(error)

    return result


def get_dns_records(hostname):

    result = {
        "A": [],
        "AAAA": [],
        "MX": [],
        "NS": []
    }

    record_types = [
        "A",
        "AAAA",
        "MX",
        "NS"
    ]

    for record_type in record_types:

        try:

            answers = dns.resolver.resolve(
                hostname,
                record_type,
                lifetime=5
            )

            for answer in answers:

                result[record_type].append(
                    str(answer)
                )

        except Exception:
            pass

    return result


def detect_technology(response):

    headers = response.headers
    content = response.text.lower()

    technologies = []

    server = headers.get("Server")

    if server:
        technologies.append({
            "name": "Web Server",
            "value": server
        })

    powered_by = headers.get(
        "X-Powered-By"
    )

    if powered_by:
        technologies.append({
            "name": "X-Powered-By",
            "value": powered_by
        })

    if "cloudflare" in (
        headers.get("Server", "").lower()
    ):
        technologies.append({
            "name": "Cloudflare",
            "value": "Detected"
        })

    technology_checks = [
        ("WordPress", "wp-content"),
        ("WordPress", "wp-includes"),
        ("Drupal", "drupalSettings"),
        ("Joomla", "/media/system/"),
        ("React", "react"),
        ("Next.js", "_next/"),
        ("Angular", "ng-version"),
        ("Vue", "vue"),
        ("Bootstrap", "bootstrap"),
        ("jQuery", "jquery"),
        ("PHP", ".php"),
        ("Django", "csrfmiddlewaretoken"),
        ("Laravel", "laravel_session"),
        ("Nginx", "nginx"),
        ("Apache", "apache")
    ]

    found = set()

    for name, pattern in technology_checks:

        if name in found:
            continue

        if pattern.lower() in content:

            technologies.append({
                "name": name,
                "value": "Detected"
            })

            found.add(name)

    return technologies


def analyze_security_headers(response):

    present = []
    missing = []

    for header in SECURITY_HEADERS:

        if response.headers.get(header):
            present.append({
                "name": header,
                "value": response.headers.get(header)
            })

        else:
            missing.append(header)

    return {
        "present": present,
        "missing": missing
    }


def analyze_cookies(response):

    cookies = []

    try:

        raw_cookies = (
            response.raw.headers.getlist(
                "Set-Cookie"
            )
        )

    except Exception:

        raw_cookies = []

    for raw_cookie in raw_cookies:

        parts = [
            part.strip()
            for part in raw_cookie.split(";")
        ]

        if not parts:
            continue

        cookie_name = parts[0].split(
            "=",
            1
        )[0]

        cookie_text = raw_cookie.lower()

        cookies.append({
            "name": cookie_name,
            "secure": "secure" in cookie_text,
            "httponly": "httponly" in cookie_text,
            "samesite": (
                "samesite=" in cookie_text
            )
        })

    return cookies


def analyze_http_security(response):

    headers = response.headers

    allow_header = headers.get("Allow")

    methods = []

    if allow_header:

        methods = [
            method.strip()
            for method in allow_header.split(",")
        ]

    return {
        "methods": methods,
        "content_type": headers.get(
            "Content-Type"
        ),
        "server": headers.get(
            "Server"
        ),
        "hsts": headers.get(
            "Strict-Transport-Security"
        ),
        "csp": headers.get(
            "Content-Security-Policy"
        ),
        "cache_control": headers.get(
            "Cache-Control"
        )
    }


def analyze_cors(response):

    headers = response.headers

    allow_origin = headers.get(
        "Access-Control-Allow-Origin"
    )

    allow_methods = headers.get(
        "Access-Control-Allow-Methods"
    )

    allow_headers = headers.get(
        "Access-Control-Allow-Headers"
    )

    allow_credentials = headers.get(
        "Access-Control-Allow-Credentials"
    )

    status = "Not Detected"

    if allow_origin:

        if allow_origin == "*":
            status = "Wildcard"
        else:
            status = "Configured"

    return {
        "status": status,
        "allow_origin": allow_origin,
        "allow_methods": allow_methods,
        "allow_headers": allow_headers,
        "allow_credentials": allow_credentials
    }


def get_owasp_checks(
    https,
    header_analysis,
    cookies,
    cors,
    vulnerabilities
):

    checks = []

    checks.append({
        "name": "HTTPS Configuration",
        "status": "PASS" if https else "FAIL",
        "description": (
            "HTTPS is enabled."
            if https
            else
            "Website is not using HTTPS."
        )
    })

    checks.append({
        "name": "Content Security Policy",
        "status": (
            "PASS"
            if "Content-Security-Policy"
            not in header_analysis["missing"]
            else "FAIL"
        ),
        "description": (
            "CSP header detected."
            if "Content-Security-Policy"
            not in header_analysis["missing"]
            else
            "CSP header is missing."
        )
    })

    checks.append({
        "name": "HSTS",
        "status": (
            "PASS"
            if "Strict-Transport-Security"
            not in header_analysis["missing"]
            else "FAIL"
        ),
        "description": (
            "HSTS detected."
            if "Strict-Transport-Security"
            not in header_analysis["missing"]
            else
            "HSTS header is missing."
        )
    })

    checks.append({
        "name": "Clickjacking Protection",
        "status": (
            "PASS"
            if "X-Frame-Options"
            not in header_analysis["missing"]
            else "FAIL"
        ),
        "description": (
            "X-Frame-Options detected."
            if "X-Frame-Options"
            not in header_analysis["missing"]
            else
            "Clickjacking protection header is missing."
        )
    })

    checks.append({
        "name": "MIME Sniffing Protection",
        "status": (
            "PASS"
            if "X-Content-Type-Options"
            not in header_analysis["missing"]
            else "FAIL"
        ),
        "description": (
            "MIME sniffing protection detected."
            if "X-Content-Type-Options"
            not in header_analysis["missing"]
            else
            "X-Content-Type-Options is missing."
        )
    })

    checks.append({
        "name": "Referrer Policy",
        "status": (
            "PASS"
            if "Referrer-Policy"
            not in header_analysis["missing"]
            else "FAIL"
        ),
        "description": (
            "Referrer-Policy detected."
            if "Referrer-Policy"
            not in header_analysis["missing"]
            else
            "Referrer-Policy is missing."
        )
    })

    checks.append({
        "name": "Permissions Policy",
        "status": (
            "PASS"
            if "Permissions-Policy"
            not in header_analysis["missing"]
            else "FAIL"
        ),
        "description": (
            "Permissions-Policy detected."
            if "Permissions-Policy"
            not in header_analysis["missing"]
            else
            "Permissions-Policy is missing."
        )
    })

    if cookies:

        insecure_cookies = []

        for cookie in cookies:

            if not cookie["secure"]:
                insecure_cookies.append(
                    cookie["name"]
                )

            if not cookie["httponly"]:
                insecure_cookies.append(
                    cookie["name"]
                )

            if not cookie["samesite"]:
                insecure_cookies.append(
                    cookie["name"]
                )

        checks.append({
            "name": "Cookie Security",
            "status": (
                "PASS"
                if not insecure_cookies
                else "REVIEW"
            ),
            "description": (
                "Cookie security flags look good."
                if not insecure_cookies
                else
                "One or more cookie security flags "
                "may be missing."
            )
        })

    else:

        checks.append({
            "name": "Cookie Security",
            "status": "REVIEW",
            "description": (
                "No cookies were detected."
            )
        })

    if cors["allow_origin"]:

        checks.append({
            "name": "CORS Configuration",
            "status": (
                "REVIEW"
                if cors["allow_origin"] == "*"
                else "PASS"
            ),
            "description": (
                "Wildcard CORS configuration detected."
                if cors["allow_origin"] == "*"
                else
                "CORS configuration detected."
            )
        })

    else:

        checks.append({
            "name": "CORS Configuration",
            "status": "REVIEW",
            "description": (
                "No CORS headers were detected."
            )
        })

    has_disclosure = any(
        finding["name"]
        in [
            "Server Information Disclosure",
            "Technology Information Disclosure"
        ]
        for finding in vulnerabilities
    )

    checks.append({
        "name": "Information Disclosure",
        "status": (
            "REVIEW"
            if has_disclosure
            else "PASS"
        ),
        "description": (
            "Some server technology information "
            "may be exposed."
            if has_disclosure
            else
            "No obvious server disclosure issue detected."
        )
    })

    return checks


def calculate_score(
    https,
    missing_headers,
    cookies,
    vulnerabilities
):

    score = 100

    if not https:
        score -= 20

    score -= len(missing_headers) * 7

    for cookie in cookies:

        if not cookie["secure"]:
            score -= 3

        if not cookie["httponly"]:
            score -= 3

        if not cookie["samesite"]:
            score -= 3

    for finding in vulnerabilities:

        severity = finding.get(
            "severity",
            "Low"
        )

        if severity == "High":
            score -= 5

        elif severity == "Medium":
            score -= 3

        elif severity == "Low":
            score -= 1

    score = max(
        0,
        min(100, score)
    )

    if score >= 80:
        risk = "Low"

    elif score >= 50:
        risk = "Medium"

    else:
        risk = "High"

    return score, risk


def create_findings(
    https,
    header_analysis,
    cookies,
    vulnerabilities
):

    findings = []

    if not https:

        findings.append({
            "severity": "High",
            "name": "HTTPS Not Enabled",
            "description": (
                "The target website is not using HTTPS."
            ),
            "recommendation": (
                "Enable HTTPS using a valid TLS certificate."
            )
        })

    for header in header_analysis["missing"]:

        findings.append({
            "severity": "Medium",
            "name": f"Missing {header}",
            "description": (
                f"The {header} security header "
                "was not detected."
            ),
            "recommendation": (
                f"Configure the {header} "
                "response header."
            )
        })

    for finding in vulnerabilities:

        findings.append(finding)

    return findings


def scan_url(url):

    original_url = normalize_url(url)

    parsed = urlparse(original_url)

    if not parsed.hostname:
        raise ValueError(
            "Invalid URL."
        )

    start_time = time.perf_counter()

    response = requests.get(
        original_url,
        headers=HEADERS,
        timeout=15,
        allow_redirects=True
    )

    response_time = round(
        time.perf_counter() - start_time,
        3
    )

    final_url = response.url

    final_parsed = urlparse(
        final_url
    )

    hostname = final_parsed.hostname

    https = (
        final_parsed.scheme.lower()
        == "https"
    )

    redirect_chain = [
        {
            "url": item.url,
            "status_code": item.status_code
        }
        for item in response.history
    ]

    redirect_chain.append({
        "url": response.url,
        "status_code": response.status_code
    })

    header_analysis = analyze_security_headers(
        response
    )

    cookies = analyze_cookies(
        response
    )

    technology = detect_technology(
        response
    )

    http_security = analyze_http_security(
        response
    )

    cors = analyze_cors(
        response
    )

    ssl_info = {}

    if hostname and https:

        ssl_info = get_ssl_info(
            hostname
        )

    else:

        ssl_info = {
            "status": "Not Applicable",
            "tls_version": None,
            "cipher": None,
            "issuer": None,
            "subject": None,
            "expires": None,
            "days_remaining": None,
            "error": None
        }

    dns_records = get_dns_records(
        hostname
    )

    vulnerabilities = run_vulnerability_scan(
        final_url,
        response
    )

    owasp = get_owasp_checks(
        https,
        header_analysis,
        cookies,
        cors,
        vulnerabilities
    )

    ports = scan_ports(
        hostname
    )

    recon = run_recon(
        final_url
    )

    security_score, risk_level = calculate_score(
        https,
        header_analysis["missing"],
        cookies,
        vulnerabilities
    )

    findings = create_findings(
        https,
        header_analysis,
        cookies,
        vulnerabilities
    )

    summary = {
        "headers_present": len(
            header_analysis["present"]
        ),
        "headers_missing": len(
            header_analysis["missing"]
        ),
        "cookies_count": len(
            cookies
        ),
        "findings": len(
            findings
        )
    }

    return {
        "original_url": original_url,
        "final_url": final_url,
        "status_code": response.status_code,
        "https": https,
        "redirects": len(
            response.history
        ),
        "redirect_chain": redirect_chain,
        "response_time": response_time,
        "dns": dns_records,
        "ssl": ssl_info,
        "technology": technology,
        "http_security": http_security,
        "cors": cors,
        "owasp": owasp,
        "headers": header_analysis,
        "cookies": cookies,
        "ports": ports,
        "recon": recon,
        "vulnerabilities": vulnerabilities,
        "security_score": security_score,
        "risk_level": risk_level,
        "summary": summary,
        "findings": findings
    }