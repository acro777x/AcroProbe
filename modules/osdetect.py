"""
ACROPROBE — Module: OS Detection
TTL-based heuristic + nmap OS detection.
"""

import nmap
import subprocess


TTL_MAP = {
    range(60, 65):   "Linux / Android",
    range(126, 129): "Windows",
    range(253, 256): "Cisco / Network Device",
    range(30, 35):   "Unix / Solaris",
}


def ttl_guess(host: str) -> str:
    """Quick TTL-based OS guess from ping."""
    try:
        output = subprocess.check_output(
            ["ping", "-c", "1", "-W", "1", host],
            stderr=subprocess.DEVNULL
        ).decode()
        for line in output.splitlines():
            if "ttl=" in line.lower():
                ttl = int(line.lower().split("ttl=")[1].split()[0])
                for ttl_range, os_name in TTL_MAP.items():
                    if ttl in ttl_range:
                        return os_name
    except Exception:
        pass
    return "Unknown"


def detect_os(host: str) -> str:
    """
    Full OS detection using nmap -O with TTL fallback.
    Requires root.
    """
    nm = nmap.PortScanner()
    try:
        nm.scan(host, arguments="-O --osscan-guess -T4")
        if host in nm.all_hosts():
            osmatch = nm[host].get("osmatch", [])
            if osmatch:
                best = osmatch[0]
                return f"{best['name']} (confidence: {best['accuracy']}%)"
    except Exception:
        pass

    # Fallback to TTL
    return ttl_guess(host)
