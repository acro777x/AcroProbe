"""
ACROPROBE — Module: Host Discovery
Uses ARP for local subnets, ICMP for wider ranges.
"""

import subprocess
from scapy.all import ARP, Ether, srp


def discover_hosts(target: str) -> list:
    """
    Discover all live hosts in the target range.
    Returns list of IP addresses.
    """
    live_hosts = []

    try:
        # ARP sweep — fast and reliable on local subnets
        arp = ARP(pdst=target)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether / arp
        result = srp(packet, timeout=3, verbose=False)[0]

        for _, received in result:
            live_hosts.append(received.psrc)

    except Exception:
        # Fallback: nmap ping scan
        try:
            output = subprocess.check_output(
                ["nmap", "-sn", target, "--open", "-oG", "-"],
                stderr=subprocess.DEVNULL
            ).decode()
            for line in output.splitlines():
                if "Host:" in line and "Status: Up" in line:
                    parts = line.split()
                    live_hosts.append(parts[1])
        except Exception as e:
            print(f"[discovery] Error: {e}")

    return list(set(live_hosts))
