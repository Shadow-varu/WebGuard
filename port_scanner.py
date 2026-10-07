import socket


COMMON_PORTS = {
    20: "FTP-Data",
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    465: "SMTPS",
    587: "SMTP Submission",
    993: "IMAPS",
    995: "POP3S",
    1433: "MSSQL",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    8080: "HTTP-Proxy",
    8443: "HTTPS-Alt",
}


def scan_ports(host, timeout=0.5):

    result = {
        "host": host,
        "ip": None,
        "open_ports": [],
        "scanned_ports": len(COMMON_PORTS),
        "error": None
    }

    if not host:

        result["error"] = (
            "Host not provided."
        )

        return result

    try:

        ip_address = socket.gethostbyname(
            host
        )

        result["ip"] = ip_address

    except socket.gaierror:

        result["error"] = (
            "Unable to resolve hostname."
        )

        return result

    for port, service in COMMON_PORTS.items():

        sock = socket.socket(
            socket.AF_INET,
            socket.SOCK_STREAM
        )

        sock.settimeout(timeout)

        try:

            connection = sock.connect_ex(
                (ip_address, port)
            )

            if connection == 0:

                result["open_ports"].append({

                    "port": port,

                    "service": service,

                    "status": "Open"

                })

        except socket.error:
            pass

        finally:
            sock.close()

    return result