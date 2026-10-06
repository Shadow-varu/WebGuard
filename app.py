from flask import Flask, render_template, request, send_file, make_response
import io
import json
import ipaddress
import socket

from scanner import scan_url

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_CENTER
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle
)

app = Flask(__name__)


# ============================================================
# SECURITY VALIDATION
# ============================================================

def is_private_or_local_host(hostname):
    if not hostname:
        return True

    hostname = hostname.strip().lower().rstrip(".")

    blocked_names = {
        "localhost",
        "localhost.localdomain",
        "ip6-localhost",
        "ip6-loopback",
        "local"
    }

    if hostname in blocked_names:
        return True

    # Direct IP address check
    try:
        ip = ipaddress.ip_address(hostname)

        return (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_reserved
            or ip.is_multicast
            or ip.is_unspecified
        )

    except ValueError:
        pass

    # Domain name
    # NOTE:
    # We do NOT reject normal public domains just because
    # DNS resolution fails here.
    #
    # This prevents example.com from being incorrectly
    # classified as a private/local address.

    return False


def validate_target(url):
    if not url:
        return False, "Please enter a website URL."

    url = url.strip()

    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    try:
        from urllib.parse import urlparse

        parsed = urlparse(url)

        if parsed.scheme not in ("http", "https"):
            return False, "Only HTTP and HTTPS URLs are allowed."

        if not parsed.hostname:
            return False, "Invalid website URL."

        hostname = parsed.hostname

        if is_private_or_local_host(hostname):
            return (
                False,
                "Private or local IP addresses are not allowed."
            )

        return True, url

    except Exception:
        return False, "Invalid website URL."


# ============================================================
# JSON HELPER
# ============================================================

def safe_json(data):
    try:
        return json.dumps(
            data,
            indent=2,
            default=str
        )
    except Exception:
        return "{}"


# ============================================================
# HOME / SCANNER
# ============================================================

@app.route("/", methods=["GET", "POST"])
def index():

    result = None
    error = None
    scanned_url = ""

    if request.method == "POST":

        scanned_url = request.form.get(
            "url",
            ""
        ).strip()

        valid, validated_url = validate_target(
            scanned_url
        )

        if not valid:
            error = validated_url

            return render_template(
                "index.html",
                result=None,
                error=error,
                scanned_url=scanned_url
            )

        try:

            result = scan_url(
                validated_url
            )

            if not result:
                error = "Scanner returned no result."

        except Exception as exc:

            error = f"Scan failed: {str(exc)}"

    return render_template(
        "index.html",
        result=result,
        error=error,
        scanned_url=scanned_url
    )


# ============================================================
# HTML REPORT
# ============================================================

@app.route(
    "/generate-report",
    methods=["POST"]
)
def generate_report():

    report_data = request.form.get(
        "report_data",
        ""
    )

    if not report_data:
        return "No report data available.", 400

    try:

        result = json.loads(
            report_data
        )

    except json.JSONDecodeError:

        return "Invalid report data.", 400

    html = build_html_report(
        result
    )

    response = make_response(
        html
    )

    response.headers[
        "Content-Type"
    ] = "text/html"

    response.headers[
        "Content-Disposition"
    ] = (
        "attachment; "
        "filename=webguard_security_report.html"
    )

    return response


def build_html_report(result):

    score = result.get(
        "security_score",
        "N/A"
    )

    risk = result.get(
        "risk_level",
        "N/A"
    )

    original_url = result.get(
        "original_url",
        "N/A"
    )

    final_url = result.get(
        "final_url",
        "N/A"
    )

    status_code = result.get(
        "status_code",
        "N/A"
    )

    response_time = result.get(
        "response_time",
        "N/A"
    )

    sections = [
        (
            "SSL / TLS",
            result.get("ssl", {})
        ),
        (
            "DNS Information",
            result.get("dns", {})
        ),
        (
            "Technology Detection",
            result.get("technology", {})
        ),
        (
            "Security Headers",
            result.get("headers", {})
        ),
        (
            "Cookie Security",
            result.get("cookies", [])
        ),
        (
            "CORS Analysis",
            result.get("cors", {})
        ),
        (
            "OWASP-style Checks",
            result.get("owasp", {})
        ),
        (
            "Port Scan",
            result.get("ports", {})
        ),
        (
            "Reconnaissance",
            result.get("recon", {})
        ),
        (
            "Passive Vulnerability Analysis",
            result.get("vulnerabilities", [])
        ),
        (
            "Security Findings",
            result.get("findings", [])
        )
    ]

    sections_html = ""

    for title, data in sections:

        sections_html += f"""
        <div class="card">
            <h2>{title}</h2>
            <pre>{safe_json(data)}</pre>
        </div>
        """

    html = f"""
<!DOCTYPE html>
<html>
<head>

<meta charset="UTF-8">

<title>
WebGuard Security Report
</title>

<style>

body {{
    font-family:
        Arial,
        sans-serif;

    background:
        #0b1220;

    color:
        #e8eefc;

    margin:
        0;

    padding:
        40px;
}}

.container {{
    max-width:
        1100px;

    margin:
        auto;
}}

h1 {{
    color:
        #29a9ff;
}}

h2 {{
    color:
        #72c7ff;
}}

.card {{
    background:
        #141f33;

    border:
        1px solid #2a3a55;

    border-radius:
        12px;

    padding:
        20px;

    margin-bottom:
        20px;
}}

.score {{
    font-size:
        48px;

    font-weight:
        bold;
}}

table {{
    width:
        100%;

    border-collapse:
        collapse;
}}

th,
td {{
    padding:
        10px;

    border-bottom:
        1px solid #30415e;

    text-align:
        left;
}}

th {{
    color:
        #72c7ff;
}}

pre {{
    white-space:
        pre-wrap;

    word-break:
        break-word;
}}

</style>

</head>

<body>

<div class="container">

<h1>
🛡️ WebGuard Security Report
</h1>

<div class="card">

<h2>
Security Score
</h2>

<div class="score">
{score}/100
</div>

<p>
Risk Level:
<strong>{risk}</strong>
</p>

</div>


<div class="card">

<h2>
Website Information
</h2>

<table>

<tr>
<th>Original URL</th>
<td>{original_url}</td>
</tr>

<tr>
<th>Final URL</th>
<td>{final_url}</td>
</tr>

<tr>
<th>Status Code</th>
<td>{status_code}</td>
</tr>

<tr>
<th>Response Time</th>
<td>{response_time}</td>
</tr>

</table>

</div>


{sections_html}

</div>

</body>
</html>
"""

    return html


# ============================================================
# PDF REPORT
# ============================================================

@app.route(
    "/generate-pdf",
    methods=["POST"]
)
def generate_pdf():

    report_data = request.form.get(
        "report_data",
        ""
    )

    if not report_data:
        return "No report data available.", 400

    try:

        result = json.loads(
            report_data
        )

    except json.JSONDecodeError:

        return "Invalid report data.", 400

    pdf_buffer = io.BytesIO()

    document = SimpleDocTemplate(
        pdf_buffer,
        pagesize=A4,
        rightMargin=35,
        leftMargin=35,
        topMargin=35,
        bottomMargin=35
    )

    styles = getSampleStyleSheet()

    title_style = ParagraphStyle(
        "WebGuardTitle",
        parent=styles["Title"],
        alignment=TA_CENTER,
        fontSize=22,
        spaceAfter=20
    )

    heading_style = ParagraphStyle(
        "WebGuardHeading",
        parent=styles["Heading2"],
        fontSize=15,
        spaceBefore=15,
        spaceAfter=10
    )

    body_style = ParagraphStyle(
        "WebGuardBody",
        parent=styles["BodyText"],
        fontSize=9,
        leading=13
    )

    story = []

    score = result.get(
        "security_score",
        "N/A"
    )

    risk = result.get(
        "risk_level",
        "N/A"
    )

    original_url = result.get(
        "original_url",
        "N/A"
    )

    final_url = result.get(
        "final_url",
        "N/A"
    )

    status_code = result.get(
        "status_code",
        "N/A"
    )

    response_time = result.get(
        "response_time",
        "N/A"
    )

    story.append(
        Paragraph(
            "WebGuard Security Report",
            title_style
        )
    )

    story.append(
        Paragraph(
            f"<b>Security Score:</b> "
            f"{score}/100",
            body_style
        )
    )

    story.append(
        Paragraph(
            f"<b>Risk Level:</b> "
            f"{risk}",
            body_style
        )
    )

    story.append(
        Spacer(1, 15)
    )

    website_table = Table(
        [
            ["Field", "Value"],
            ["Original URL", str(original_url)],
            ["Final URL", str(final_url)],
            ["Status Code", str(status_code)],
            ["Response Time", str(response_time)]
        ],
        colWidths=[
            150,
            350
        ]
    )

    website_table.setStyle(
        TableStyle(
            [
                (
                    "BACKGROUND",
                    (0, 0),
                    (-1, 0),
                    colors.HexColor("#1d3557")
                ),
                (
                    "TEXTCOLOR",
                    (0, 0),
                    (-1, 0),
                    colors.white
                ),
                (
                    "GRID",
                    (0, 0),
                    (-1, -1),
                    0.5,
                    colors.grey
                ),
                (
                    "VALIGN",
                    (0, 0),
                    (-1, -1),
                    "TOP"
                ),
                (
                    "FONTNAME",
                    (0, 0),
                    (-1, 0),
                    "Helvetica-Bold"
                ),
                (
                    "FONTSIZE",
                    (0, 0),
                    (-1, -1),
                    8
                ),
                (
                    "BOTTOMPADDING",
                    (0, 0),
                    (-1, -1),
                    7
                ),
                (
                    "TOPPADDING",
                    (0, 0),
                    (-1, -1),
                    7
                )
            ]
        )
    )

    story.append(
        website_table
    )

    sections = [
        (
            "SSL / TLS",
            result.get("ssl", {})
        ),
        (
            "DNS Information",
            result.get("dns", {})
        ),
        (
            "Technology Detection",
            result.get("technology", {})
        ),
        (
            "Security Headers",
            result.get("headers", {})
        ),
        (
            "Cookie Security",
            result.get("cookies", [])
        ),
        (
            "CORS Analysis",
            result.get("cors", {})
        ),
        (
            "OWASP-style Checks",
            result.get("owasp", {})
        ),
        (
            "Port Scan",
            result.get("ports", {})
        ),
        (
            "Reconnaissance",
            result.get("recon", {})
        ),
        (
            "Passive Vulnerability Analysis",
            result.get(
                "vulnerabilities",
                []
            )
        ),
        (
            "Security Findings",
            result.get(
                "findings",
                []
            )
        )
    ]

    for title, data in sections:

        story.append(
            Paragraph(
                title,
                heading_style
            )
        )

        formatted = safe_json(
            data
        )

        formatted = (
            formatted
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace("\n", "<br/>")
        )

        chunks = [
            formatted[i:i + 5000]
            for i in range(
                0,
                len(formatted),
                5000
            )
        ]

        if not chunks:
            chunks = [
                "No data available."
            ]

        for chunk in chunks:

            story.append(
                Paragraph(
                    chunk,
                    body_style
                )
            )

            story.append(
                Spacer(1, 8)
            )

    document.build(
        story
    )

    pdf_buffer.seek(0)

    return send_file(
        pdf_buffer,
        as_attachment=True,
        download_name=(
            "webguard_security_report.pdf"
        ),
        mimetype="application/pdf"
    )


# ============================================================
# ERROR HANDLERS
# ============================================================

@app.errorhandler(404)
def page_not_found(error):

    return render_template(
        "index.html",
        result=None,
        error="Page not found.",
        scanned_url=""
    ), 404


@app.errorhandler(500)
def internal_server_error(error):

    return render_template(
        "index.html",
        result=None,
        error="Internal server error.",
        scanned_url=""
    ), 500


# ============================================================
# START SERVER
# ============================================================

if __name__ == "__main__":

    print("=" * 60)
    print("WebGuard - Web Security Scanner")
    print("=" * 60)
    print(
        "Local URL: "
        "http://127.0.0.1:5000"
    )
    print("Scanner ready.")
    print("=" * 60)

    app.run(
        host="127.0.0.1",
        port=5000,
        debug=True
    )