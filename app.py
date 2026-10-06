from flask import (
    Flask,
    render_template,
    request,
    send_file,
    make_response
)

import io
import ipaddress
import json
import socket
from urllib.parse import urlparse

from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Preformatted
)

from scanner import scan_url


app = Flask(__name__)

# ============================================================
# WEBGUARD CONFIGURATION
# ============================================================

APP_NAME = "WebGuard"
APP_VERSION = "4.0"

LIVE_URL = "https://webguard-43l3.onrender.com"
GITHUB_URL = "https://github.com/Shadow-varu/WebGuard"

MAX_REPORT_SIZE = 5 * 1024 * 1024


# ============================================================
# HOST VALIDATION
# ============================================================

def is_private_or_local_host(hostname):
    """
    Blocks obvious local/private IP targets.

    WebGuard is intended for websites and systems
    that the user owns or is authorized to assess.
    """

    if not hostname:
        return True

    hostname = hostname.strip().lower().rstrip(".")

    blocked_names = {
        "localhost",
        "localhost.localdomain",
        "local",
        "ip6-localhost",
        "ip6-loopback"
    }

    if hostname in blocked_names:
        return True

    # Direct IP address check
    try:
        ip = ipaddress.ip_address(hostname)

        if (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_reserved
            or ip.is_multicast
            or ip.is_unspecified
        ):
            return True

    except ValueError:
        # Hostname is not an IP address.
        pass

    return False


# ============================================================
# URL VALIDATION
# ============================================================

def validate_target(url):
    """
    Validate target URL before scanning.
    """

    if not url:
        return False, "Please enter a website URL."

    url = url.strip()

    # Add HTTPS automatically
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    try:
        parsed = urlparse(url)
    except Exception:
        return False, "Invalid URL."

    if parsed.scheme.lower() not in ("http", "https"):
        return False, "Only HTTP and HTTPS URLs are allowed."

    if not parsed.hostname:
        return False, "Please enter a valid hostname."

    hostname = parsed.hostname

    if is_private_or_local_host(hostname):
        return False, (
            "Private, loopback, local or reserved IP addresses "
            "are not allowed."
        )

    return True, url


# ============================================================
# SAFE JSON
# ============================================================

def safe_json(data):
    """
    Convert Python data into JSON safely.
    """

    try:
        return json.dumps(
            data,
            indent=2,
            ensure_ascii=False,
            default=str
        )
    except Exception:
        return "{}"


# ============================================================
# HOME PAGE
# ============================================================

@app.route("/", methods=["GET", "POST"])
def index():

    result = None
    error = None
    target_url = ""

    if request.method == "POST":

        target_url = request.form.get("url", "").strip()

        valid, validated_url = validate_target(target_url)

        if not valid:
            error = validated_url

        else:
            try:
                result = scan_url(validated_url)

            except Exception as exc:
                error = f"Scan failed: {str(exc)}"

    return render_template(
        "index.html",
        result=result,
        error=error,
        target_url=target_url
    )


# ============================================================
# ROBOTS.TXT
# ============================================================

@app.route("/robots.txt")
def robots_txt():

    robots = f"""User-agent: *
Allow: /

Sitemap: {LIVE_URL}/sitemap.xml
"""

    response = make_response(robots)
    response.headers["Content-Type"] = "text/plain; charset=utf-8"

    return response


# ============================================================
# SITEMAP.XML
# ============================================================

@app.route("/sitemap.xml")
def sitemap_xml():

    sitemap = f"""<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">

    <url>
        <loc>{LIVE_URL}/</loc>
        <changefreq>weekly</changefreq>
        <priority>1.0</priority>
    </url>

</urlset>
"""

    response = make_response(sitemap)
    response.headers["Content-Type"] = "application/xml; charset=utf-8"

    return response


# ============================================================
# HTML REPORT
# ============================================================

@app.route("/generate-report", methods=["POST"])
def generate_report():

    raw_data = request.form.get("report_data", "")

    if not raw_data:
        return "No report data provided.", 400

    if len(raw_data) > MAX_REPORT_SIZE:
        return "Report data is too large.", 413

    try:
        report_data = json.loads(raw_data)

    except json.JSONDecodeError:
        return "Invalid report data.", 400

    formatted_json = safe_json(report_data)

    target = (
        report_data.get("final_url")
        or report_data.get("original_url")
        or "Unknown Target"
    )

    score = report_data.get(
        "security_score",
        "N/A"
    )

    risk = report_data.get(
        "risk_level",
        "N/A"
    )

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>

<meta charset="UTF-8">

<meta name="viewport"
      content="width=device-width, initial-scale=1.0">

<title>WebGuard Security Report</title>

<style>

body {{
    font-family: Arial, sans-serif;
    background: #0b0b12;
    color: #eeeeee;
    margin: 0;
    padding: 40px;
}}

.container {{
    max-width: 1000px;
    margin: auto;
}}

h1 {{
    color: #8b5cf6;
}}

h2 {{
    margin-top: 35px;
    color: #c4b5fd;
}}

.card {{
    background: #151521;
    border: 1px solid #2b2b40;
    border-radius: 12px;
    padding: 20px;
    margin-bottom: 20px;
}}

.score {{
    font-size: 42px;
    font-weight: bold;
}}

pre {{
    background: #09090f;
    padding: 20px;
    border-radius: 10px;
    overflow-x: auto;
    white-space: pre-wrap;
    word-break: break-word;
}}

.footer {{
    margin-top: 40px;
    padding-top: 20px;
    border-top: 1px solid #333;
    color: #999;
}}

</style>

</head>

<body>

<div class="container">

<h1>WebGuard Security Report</h1>

<div class="card">

<strong>Target:</strong>
{target}

<br><br>

<strong>Security Score:</strong>

<div class="score">
{score}/100
</div>

<strong>Risk Level:</strong>
{risk}

</div>

<h2>Scan Results</h2>

<div class="card">

<pre>{formatted_json}</pre>

</div>

<div class="footer">

<strong>WebGuard</strong> — Web Security Scanner

<br><br>

Developed by <strong>Veeresh S.</strong>

<br><br>

GitHub:
<a href="{GITHUB_URL}" target="_blank">
{GITHUB_URL}
</a>

<br><br>

Use WebGuard only on websites and systems
you own or are authorized to assess.

</div>

</div>

</body>
</html>
"""

    response = make_response(html)

    response.headers["Content-Type"] = "text/html; charset=utf-8"

    response.headers[
        "Content-Disposition"
    ] = "attachment; filename=WebGuard_Security_Report.html"

    return response


# ============================================================
# PDF REPORT
# ============================================================

@app.route("/generate-pdf", methods=["POST"])
def generate_pdf():

    raw_data = request.form.get("report_data", "")

    if not raw_data:
        return "No report data provided.", 400

    if len(raw_data) > MAX_REPORT_SIZE:
        return "Report data is too large.", 413

    try:
        report_data = json.loads(raw_data)

    except json.JSONDecodeError:
        return "Invalid report data.", 400

    target = (
        report_data.get("final_url")
        or report_data.get("original_url")
        or "Unknown Target"
    )

    score = report_data.get(
        "security_score",
        "N/A"
    )

    risk = report_data.get(
        "risk_level",
        "N/A"
    )

    formatted_json = safe_json(report_data)

    pdf_buffer = io.BytesIO()

    document = SimpleDocTemplate(
        pdf_buffer,
        pagesize=A4,
        rightMargin=40,
        leftMargin=40,
        topMargin=40,
        bottomMargin=40
    )

    styles = getSampleStyleSheet()

    title_style = styles["Title"]
    heading_style = styles["Heading2"]
    normal_style = styles["BodyText"]

    story = []

    # Title
    story.append(
        Paragraph(
            "WebGuard Security Report",
            title_style
        )
    )

    story.append(
        Spacer(1, 15)
    )

    # Target
    story.append(
        Paragraph(
            f"<b>Target:</b> {target}",
            normal_style
        )
    )

    story.append(
        Spacer(1, 10)
    )

    # Score
    story.append(
        Paragraph(
            f"<b>Security Score:</b> {score}/100",
            normal_style
        )
    )

    story.append(
        Spacer(1, 10)
    )

    # Risk
    story.append(
        Paragraph(
            f"<b>Risk Level:</b> {risk}",
            normal_style
        )
    )

    story.append(
        Spacer(1, 20)
    )

    # Results
    story.append(
        Paragraph(
            "Scan Results",
            heading_style
        )
    )

    story.append(
        Spacer(1, 10)
    )

    story.append(
        Preformatted(
            formatted_json,
            styles["Code"]
        )
    )

    story.append(
        Spacer(1, 25)
    )

    # Developer
    story.append(
        Paragraph(
            "<b>WebGuard</b> — Web Security Scanner",
            normal_style
        )
    )

    story.append(
        Spacer(1, 8)
    )

    story.append(
        Paragraph(
            "Developed by <b>Veeresh S.</b>",
            normal_style
        )
    )

    story.append(
        Spacer(1, 8)
    )

    story.append(
        Paragraph(
            "GitHub: "
            f"{GITHUB_URL}",
            normal_style
        )
    )

    story.append(
        Spacer(1, 8)
    )

    story.append(
        Paragraph(
            "Use WebGuard only on websites and systems "
            "you own or are authorized to assess.",
            normal_style
        )
    )

    document.build(story)

    pdf_buffer.seek(0)

    return send_file(
        pdf_buffer,
        mimetype="application/pdf",
        as_attachment=True,
        download_name="WebGuard_Security_Report.pdf"
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
        target_url=""
    ), 404


@app.errorhandler(500)
def internal_server_error(error):

    return render_template(
        "index.html",
        result=None,
        error="Internal server error. Please try again.",
        target_url=""
    ), 500


# ============================================================
# APPLICATION START
# ============================================================

if __name__ == "__main__":

    app.run(
        host="127.0.0.1",
        port=5000,
        debug=True
    )