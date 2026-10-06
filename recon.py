import requests
from urllib.parse import urlparse


HEADERS = {
    "User-Agent": "WebGuard/4.0 Security Scanner"
}


def get_base_url(url):
    parsed = urlparse(url)

    if not parsed.hostname:
        return None

    return f"{parsed.scheme}://{parsed.netloc}"


def get_host(url):
    parsed = urlparse(url)
    return parsed.hostname


def check_robots_txt(url):

    base_url = get_base_url(url)

    result = {
        "url": None,
        "status": "Not Found",
        "status_code": None,
        "content": "",
        "error": None
    }

    if not base_url:
        result["status"] = "Error"
        result["error"] = "Invalid URL"
        return result

    robots_url = base_url + "/robots.txt"

    result["url"] = robots_url

    try:
        response = requests.get(
            robots_url,
            headers=HEADERS,
            timeout=5,
            allow_redirects=True
        )

        result["status_code"] = response.status_code

        if response.status_code == 200:

            result["status"] = "Found"

            result["content"] = response.text[:10000]

        else:
            result["status"] = "Not Found"

    except requests.RequestException as error:

        result["status"] = "Error"
        result["error"] = str(error)

    return result


def check_sitemap(url):

    base_url = get_base_url(url)

    result = {
        "status": "Not Found",
        "url": None,
        "status_code": None,
        "error": None
    }

    if not base_url:
        result["status"] = "Error"
        result["error"] = "Invalid URL"
        return result

    sitemap_urls = [
        base_url + "/sitemap.xml",
        base_url + "/sitemap_index.xml"
    ]

    for sitemap_url in sitemap_urls:

        try:

            response = requests.get(
                sitemap_url,
                headers=HEADERS,
                timeout=5,
                allow_redirects=True
            )

            if response.status_code == 200:

                result["status"] = "Found"
                result["url"] = sitemap_url
                result["status_code"] = response.status_code

                return result

        except requests.RequestException:
            continue

    return result


def discover_subdomains(url):

    host = get_host(url)

    if not host:
        return []

    if host.startswith("www."):
        host = host[4:]

    common_subdomains = [
        "www",
        "mail",
        "ftp",
        "api",
        "dev",
        "test",
        "staging",
        "admin",
        "blog",
        "shop",
        "app",
        "portal",
        "cdn",
        "static",
        "support"
    ]

    discovered = []

    for subdomain in common_subdomains:

        hostname = f"{subdomain}.{host}"

        try:

            response = requests.get(
                "https://" + hostname,
                headers=HEADERS,
                timeout=2,
                allow_redirects=True
            )

            discovered.append({
                "subdomain": hostname,
                "url": response.url,
                "status_code": response.status_code
            })

        except requests.RequestException:
            pass

    return discovered


def analyze_robots_content(content):

    result = {
        "user_agents": [],
        "disallowed": [],
        "allowed": [],
        "sitemaps": []
    }

    if not content:
        return result

    for line in content.splitlines():

        line = line.strip()

        if not line or line.startswith("#"):
            continue

        if ":" not in line:
            continue

        key, value = line.split(":", 1)

        key = key.strip().lower()
        value = value.strip()

        if key == "user-agent":
            result["user_agents"].append(value)

        elif key == "disallow":
            result["disallowed"].append(value)

        elif key == "allow":
            result["allowed"].append(value)

        elif key == "sitemap":
            result["sitemaps"].append(value)

    return result


def run_recon(url):

    robots = check_robots_txt(url)

    robots_analysis = analyze_robots_content(
        robots.get("content", "")
    )

    sitemap = check_sitemap(url)

    subdomains = discover_subdomains(url)

    return {
        "robots": robots,
        "robots_analysis": robots_analysis,
        "sitemap": sitemap,
        "subdomains": subdomains
    }