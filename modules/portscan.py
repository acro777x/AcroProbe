"""
ACROPROBE — Module: Port Scanner & Service Fingerprinter
"""

import nmap

# Port ranges
PORT_RANGES = {
    "common":   "21,22,23,25,53,80,110,135,139,143,443,445,3306,3389,5900,8080,8443",
    "extended": "1-1024,1433,1521,2049,3306,3389,5432,5900,6379,8080,8443,9200,27017",
    "all":      "1-65535"
}


def scan_ports(host: str, mode: str = "common") -> dict:
    """
    Scan a host for open ports, grab service banners and versions.
    Returns structured dict of findings.
    """
    nm = nmap.PortScanner()
    ports = PORT_RANGES.get(mode, PORT_RANGES["common"])

    try:
        nm.scan(host, ports, arguments="-sV -T4 --open")
    except Exception as e:
        return {"error": str(e), "open_ports": [], "services": {}}

    open_ports = []
    services = {}

    if host in nm.all_hosts():
        for proto in nm[host].all_protocols():
            for port in nm[host][proto].keys():
                state = nm[host][proto][port]["state"]
                if state == "open":
                    open_ports.append(port)
                    services[port] = {
                        "protocol": proto,
                        "state":    state,
                        "name":     nm[host][proto][port].get("name", "unknown"),
                        "product":  nm[host][proto][port].get("product", ""),
                        "version":  nm[host][proto][port].get("version", ""),
                        "extrainfo": nm[host][proto][port].get("extrainfo", ""),
                    }

    return {
        "open_ports": open_ports,
        "services":   services,
        "mac":        nm[host]["addresses"].get("mac", "N/A") if host in nm.all_hosts() else "N/A"
    }
