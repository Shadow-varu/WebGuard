import ipaddress
import socket
from urllib.parse import urlparse


def is_private_or_local_ip(ip):
    try:
        address = ipaddress.ip_address(ip)

        return (
            address.is_private
            or address.is_loopback
            or address.is_link_local
            or address.is_multicast
            or address.is_reserved
            or address.is_unspecified
        )

    except ValueError:
        return True


def validate_target_url(url):
    if not url:
        return False, "URL is required."

    url = url.strip()

    if len(url) > 2048:
        return False, "URL is too long."

    try:
        parsed = urlparse(url)

        if parsed.scheme not in ("http", "https"):
            return False, "Only HTTP and HTTPS URLs are allowed."

        if not parsed.hostname:
            return False, "Invalid hostname."

        hostname = parsed.hostname.lower()

        blocked_names = {
            "localhost",
            "localhost.localdomain",
            "ip6-localhost",
            "ip6-loopback",
        }

        if hostname in blocked_names:
            return False, "Localhost targets are not allowed."

        try:
            if is_private_or_local_ip(hostname):
                return False, (
                    "Private or local IP addresses are not allowed."
                )
        except Exception:
            pass

        try:
            addresses = socket.getaddrinfo(
                hostname,
                None,
                type=socket.SOCK_STREAM
            )

            checked_ips = set()

            for address in addresses:
                ip = address[4][0]

                if ip in checked_ips:
                    continue

                checked_ips.add(ip)

                if is_private_or_local_ip(ip):
                    return False, (
                        "The target resolves to a private "
                        "or local IP address."
                    )

        except socket.gaierror:
            return False, "Unable to resolve hostname."

        return True, "URL is valid."

    except Exception:
        return False, "Invalid URL."