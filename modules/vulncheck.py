"""
ACROPROBE — Module: Vulnerability Flag Checker
Pattern-based flags against open services.
Not a full CVE scanner — flags known risky service/port combos
for investigator attention.
"""

# Known risky port/service patterns
# Format: (port, service_keyword, flag_message, severity)
VULN_PATTERNS = [
    (21,    "ftp",        "FTP open — credentials sent in plaintext",                "HIGH"),
    (23,    "telnet",     "Telnet open — unencrypted remote access",                 "CRITICAL"),
    (445,   "smb",        "SMB open — check MS17-010 (EternalBlue / WannaCry)",      "CRITICAL"),
    (3389,  "ms-wbt",     "RDP exposed — brute-force and BlueKeep risk",             "HIGH"),
    (5900,  "vnc",        "VNC open — check for no-auth or weak auth",               "HIGH"),
    (3306,  "mysql",      "MySQL port exposed — check for remote root access",       "MEDIUM"),
    (5432,  "postgresql", "PostgreSQL exposed externally",                           "MEDIUM"),
    (6379,  "redis",      "Redis open — often unauthenticated by default",           "HIGH"),
    (27017, "mongodb",    "MongoDB exposed — check for unauthenticated access",      "HIGH"),
    (9200,  "elasticsearch", "Elasticsearch open — often no auth by default",        "HIGH"),
    (2049,  "nfs",        "NFS mount exposed — check for unrestricted shares",       "MEDIUM"),
    (25,    "smtp",       "SMTP open — check for open relay",                        "MEDIUM"),
    (110,   "pop3",       "POP3 open — plaintext email retrieval",                   "LOW"),
    (143,   "imap",       "IMAP open — check for plaintext auth",                   "LOW"),
    (80,    "http",       "HTTP (unencrypted) web service — check for sensitive data","LOW"),
    (8080,  "http",       "Alternate HTTP port open — check for admin panels",       "MEDIUM"),
]


def check_vulnerabilities(host_data: dict) -> list:
    """
    Cross-reference open ports and services against known risky patterns.
    Returns list of flag strings for report inclusion.
    """
    flags = []
    services = host_data.get("services", {})

    for port, service_info in services.items():
        service_name = service_info.get("name", "").lower()
        product      = service_info.get("product", "").lower()
        combined     = service_name + " " + product

        for vuln_port, keyword, message, severity in VULN_PATTERNS:
            if int(port) == vuln_port and keyword in combined:
                flags.append(f"[{severity}] Port {port} — {message}")

    return flags
