
from flask import Flask, render_template, request, send_file, make_response
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
    Preformatted,
)

from scanner import scan_url

app = Flask(__name__)

APP_NAME = "WebGuard"
APP_VERSION = "4.0"
LIVE_URL = "https://webguard-43l3.onrender.com"
GITHUB_URL = "https://github.com/Shadow-varu/WebGuard"
MAX_REPORT_SIZE = 5 * 1024 * 1024


def is_private_or_local_host(hostname):
    if not hostname:
        return True

    hostname = hostname.strip().lower().rstrip(".")

    blocked_names = {
        "localhost",
        "localhost.localdomain",
        "local",
        "ip6-localhost",
        "ip6-loopback",
    }

    if hostname in blocked_names or hostname.endswith(".localhost"):
        return True

    try:
        ip = ipaddress.ip_address(hostname)
        return not ip.is_global
    except ValueError:
        return False


def validate_target(url):
    if not url:
        return False, "Please enter a website URL."

    url = url.strip()

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

    if parsed.username or parsed.password:
        return False, "URLs containing credentials are not allowed."

    if is_private_or_local_host(parsed.hostname):
        return (
            False,
            "Private, loopback, local or reserved IP addresses are not allowed.",
        )

    return True, url


def safe_json(data):
    try:
        return json.dumps(
            data,
            indent=2,
            ensure_ascii=False,
            default=str,
        )
    except Exception:
        return "{}"


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
            except Exception:
                app.logger.exception("WebGuard scan failed")
                error = "Scan failed. Please check the URL and try again."

    return render_template(
        "index.html",
        result=result,
        error=error,
        target_url=target_url,
    )


@app.route("/robots.txt")
def robots_txt():
    robots = f"""User-agent: *
Allow: /

Sitemap: {LIVE_URL}/sitemap.xml
"""
    response = make_response(robots)
    response.headers["Content-Type"] = "text/plain; charset=utf-8"
    response.headers["Cache-Control"] = "no-cache"
    return response


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
    response.headers["Cache-Control"] = "no-cache"
    return response


@app.route("/generate-report", methods=["POST"])
def generate_report():
    raw_data = request.form.get("report_data", "")

    if not raw_data:
        return "No report data provided.", 400

    if len(raw_data) > MAX_REPORT_SIZE:
        return "Report data is too large.", 413

    try:
        report_data = json.loads(raw_data)
    except (json.JSONDecodeError, TypeError):
        return "Invalid report data.", 400

    if not isinstance(report_data, dict):
        return "Invalid report data.", 400

    target = (
        report_data.get("final_url")
        or report_data.get("original_url")
        or "Unknown Target"
    )
    score = report_data.get("security_score", "N/A")
    risk = report_data.get("risk_level", "N/A")
    formatted_json = safe_json(report_data)

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>WebGuard Security Report</title>
<style>
body{{font-family:Arial,sans-serif;background:#0b0b12;color:#eee;margin:0;padding:40px}}
.container{{max-width:1000px;margin:auto}}
h1{{color:#8b5cf6}}
h2{{color:#c4b5fd;margin-top:35px}}
.card{{background:#151521;border:1px solid #2b2b40;border-radius:12px;padding:20px;margin-bottom:20px}}
.score{{font-size:42px;font-weight:bold}}
pre{{background:#09090f;padding:20px;border-radius:10px;overflow:auto;white-space:pre-wrap;word-break:break-word}}
.footer{{margin-top:40px;padding-top:20px;border-top:1px solid #333;color:#999}}
a{{color:#a78bfa}}
</style>
</head>
<body>
<div class="container">
<h1>WebGuard Security Report</h1>
<div class="card">
<strong>Target:</strong> {target}<br><br>
<strong>Security Score:</strong>
<div class="score">{score}/100</div>
<strong>Risk Level:</strong> {risk}
</div>
<h2>Scan Results</h2>
<div class="card"><pre>{formatted_json}</pre></div>
<div class="footer">
<strong>WebGuard</strong> — Web Security Scanner<br><br>
Developed by <strong>Veeresh S.</strong><br><br>
GitHub: <a href="{GITHUB_URL}">{GITHUB_URL}</a><br><br>
Use only on systems you own or are authorized to assess.
</div>
</div>
</body>
</html>"""

    response = make_response(html)
    response.headers["Content-Type"] = "text/html; charset=utf-8"
    response.headers["Content-Disposition"] = (
        "attachment; filename=WebGuard_Security_Report.html"
    )
    return response


@app.route("/generate-pdf", methods=["POST"])
def generate_pdf():
    raw_data = request.form.get("report_data", "")

    if not raw_data:
        return "No report data provided.", 400

    if len(raw_data) > MAX_REPORT_SIZE:
        return "Report data is too large.", 413

    try:
        report_data = json.loads(raw_data)
    except (json.JSONDecodeError, TypeError):
        return "Invalid report data.", 400

    if not isinstance(report_data, dict):
        return "Invalid report data.", 400

    target = (
        report_data.get("final_url")
        or report_data.get("original_url")
        or "Unknown Target"
    )
    score = report_data.get("security_score", "N/A")
    risk = report_data.get("risk_level", "N/A")
    formatted_json = safe_json(report_data)

    pdf_buffer = io.BytesIO()

    document = SimpleDocTemplate(
        pdf_buffer,
        pagesize=A4,
        rightMargin=40,
        leftMargin=40,
        topMargin=40,
        bottomMargin=40,
    )

    styles = getSampleStyleSheet()

    story = [
        Paragraph("WebGuard Security Report", styles["Title"]),
        Spacer(1, 15),
        Paragraph(
            f"<b>Target:</b> {target}",
            styles["BodyText"],
        ),
        Spacer(1, 10),
        Paragraph(
            f"<b>Security Score:</b> {score}/100",
            styles["BodyText"],
        ),
        Spacer(1, 10),
        Paragraph(
            f"<b>Risk Level:</b> {risk}",
            styles["BodyText"],
        ),
        Spacer(1, 20),
        Paragraph("Scan Results", styles["Heading2"]),
        Spacer(1, 10),
        Preformatted(formatted_json, styles["Code"]),
        Spacer(1, 25),
        Paragraph(
            "<b>WebGuard</b> — Web Security Scanner",
            styles["BodyText"],
        ),
        Spacer(1, 8),
        Paragraph(
            "Developed by <b>Veeresh S.</b>",
            styles["BodyText"],
        ),
        Spacer(1, 8),
        Paragraph(
            f"GitHub: {GITHUB_URL}",
            styles["BodyText"],
        ),
        Spacer(1, 8),
        Paragraph(
            "Use WebGuard only on websites and systems "
            "you own or are authorized to assess.",
            styles["BodyText"],
        ),
    ]

    document.build(story)
    pdf_buffer.seek(0)

    return send_file(
        pdf_buffer,
        mimetype="application/pdf",
        as_attachment=True,
        download_name="WebGuard_Security_Report.pdf",
    )


@app.errorhandler(404)
def page_not_found(error):
    return render_template(
        "index.html",
        result=None,
        error="Page not found.",
        target_url="",
    ), 404


@app.errorhandler(500)
def internal_server_error(error):
    return render_template(
        "index.html",
        result=None,
        error="Internal server error. Please try again.",
        target_url="",
    ), 500


if __name__ == "__main__":
    app.run(
        host="127.0.0.1",
        port=5000,
        debug=False,
    )
