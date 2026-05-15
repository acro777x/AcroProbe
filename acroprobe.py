#!/usr/bin/env python3
"""
ACROPROBE — Network Reconnaissance & Forensic Threat Mapper
Part of the Acro Tool Suite | github.com/acro777x/acroprobe
Author: Ashish Kumar | Forge Labs
"""

import argparse
import datetime
import hashlib
import json
import os
import sys
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import box

from modules.discovery import discover_hosts
from modules.portscan import scan_ports
from modules.osdetect import detect_os
from modules.vulncheck import check_vulnerabilities
from modules.topology import build_topology
from report.generator import generate_report

console = Console()

BANNER = """
[bold cyan]
 █████╗  ██████╗██████╗  ██████╗ ██████╗ ██████╗  ██████╗ ██████╗ ███████╗
██╔══██╗██╔════╝██╔══██╗██╔═══██╗██╔══██╗██╔══██╗██╔═══██╗██╔══██╗██╔════╝
███████║██║     ██████╔╝██║   ██║██████╔╝██████╔╝██║   ██║██████╔╝█████╗  
██╔══██║██║     ██╔══██╗██║   ██║██╔═══╝ ██╔══██╗██║   ██║██╔══██╗██╔══╝  
██║  ██║╚██████╗██║  ██║╚██████╔╝██║     ██║  ██║╚██████╔╝██████╔╝███████╗
╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝ ╚═════╝ ╚═╝     ╚═╝  ╚═╝ ╚═════╝ ╚═════╝ ╚══════╝
[/bold cyan]
[dim]Network Reconnaissance & Forensic Threat Mapper | Acro Tool Suite[/dim]
[dim]For authorized use only. github.com/acro777x/acroprobe[/dim]
"""


def parse_args():
    parser = argparse.ArgumentParser(
        description="ACROPROBE — Network Reconnaissance & Forensic Threat Mapper",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("--target",    required=True,  help="Target IP or CIDR range (e.g. 192.168.1.0/24)")
    parser.add_argument("--output",    default="output", help="Output folder for reports (default: ./output)")
    parser.add_argument("--examiner",  default="Unknown", help="Examiner name for forensic report")
    parser.add_argument("--case",      default="N/A", help="Case ID for forensic report")
    parser.add_argument("--full",      action="store_true", help="Enable full scan (OS detection + vuln check)")
    parser.add_argument("--ports",     default="common", help="Port range: common / extended / all")
    return parser.parse_args()


def seal_integrity(data: dict) -> str:
    """SHA-256 hash of raw scan data — forensic chain of custody seal."""
    raw = json.dumps(data, sort_keys=True).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def print_summary(results: dict, integrity_hash: str):
    table = Table(box=box.ROUNDED, border_style="cyan", show_header=True)
    table.add_column("Host", style="bold white")
    table.add_column("OS", style="yellow")
    table.add_column("Open Ports", style="green")
    table.add_column("Flags", style="red")

    for host, data in results["hosts"].items():
        ports_str = ", ".join(str(p) for p in data.get("open_ports", []))
        flags_str = str(len(data.get("vuln_flags", []))) + " warning(s)"
        table.add_row(host, data.get("os", "Unknown"), ports_str or "None", flags_str)

    console.print(table)
    console.print(f"\n[dim]Integrity Hash (SHA-256): {integrity_hash}[/dim]")


def main():
    console.print(BANNER)

    args = parse_args()
    os.makedirs(args.output, exist_ok=True)

    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    scan_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S IST")

    console.print(Panel(
        f"[bold]Target:[/bold] {args.target}\n"
        f"[bold]Examiner:[/bold] {args.examiner}\n"
        f"[bold]Case ID:[/bold] {args.case}\n"
        f"[bold]Mode:[/bold] {'Full (OS + Vuln)' if args.full else 'Standard'}\n"
        f"[bold]Scan Started:[/bold] {scan_time}",
        title="[cyan]ACROPROBE SCAN SESSION[/cyan]",
        border_style="cyan"
    ))

    # ── Phase 1: Host Discovery ──────────────────────────────────────────────
    console.print("\n[cyan][Phase 1][/cyan] Discovering live hosts...")
    hosts = discover_hosts(args.target)
    console.print(f"  [green]✔[/green] {len(hosts)} host(s) found")

    results = {
        "meta": {
            "target": args.target,
            "examiner": args.examiner,
            "case_id": args.case,
            "scan_time": scan_time,
            "tool": "ACROPROBE v1.0",
            "author": "Ashish Kumar | Forge Labs"
        },
        "hosts": {}
    }

    for host in hosts:
        results["hosts"][host] = {"ip": host}

    # ── Phase 2: Port Scanning ───────────────────────────────────────────────
    console.print("\n[cyan][Phase 2][/cyan] Scanning ports and fingerprinting services...")
    for host in hosts:
        port_data = scan_ports(host, mode=args.ports)
        results["hosts"][host].update(port_data)
        open_count = len(port_data.get("open_ports", []))
        console.print(f"  [green]✔[/green] {host} — {open_count} open port(s)")

    # ── Phase 3: OS Detection ────────────────────────────────────────────────
    if args.full:
        console.print("\n[cyan][Phase 3][/cyan] Detecting operating systems...")
        for host in hosts:
            os_info = detect_os(host)
            results["hosts"][host]["os"] = os_info
            console.print(f"  [green]✔[/green] {host} — {os_info}")

    # ── Phase 4: Vulnerability Flagging ─────────────────────────────────────
    if args.full:
        console.print("\n[cyan][Phase 4][/cyan] Checking for vulnerability indicators...")
        for host in hosts:
            flags = check_vulnerabilities(results["hosts"][host])
            results["hosts"][host]["vuln_flags"] = flags
            if flags:
                console.print(f"  [red]⚠[/red]  {host} — {len(flags)} flag(s): {', '.join(flags)}")
            else:
                console.print(f"  [green]✔[/green] {host} — No flags")

    # ── Phase 5: Topology Map ────────────────────────────────────────────────
    console.print("\n[cyan][Phase 5][/cyan] Building network topology map...")
    topology_path = os.path.join(args.output, f"{timestamp}_topology.html")
    build_topology(results["hosts"], topology_path)
    console.print(f"  [green]✔[/green] Topology saved → {topology_path}")

    # ── Integrity Seal ───────────────────────────────────────────────────────
    integrity_hash = seal_integrity(results)
    results["meta"]["integrity_sha256"] = integrity_hash

    # ── Save Raw JSON ────────────────────────────────────────────────────────
    raw_path = os.path.join(args.output, f"{timestamp}_raw.json")
    with open(raw_path, "w") as f:
        json.dump(results, f, indent=2)
    console.print(f"\n[dim]Raw data saved → {raw_path}[/dim]")

    # ── Generate HTML Report ─────────────────────────────────────────────────
    console.print("\n[cyan][Phase 6][/cyan] Generating forensic HTML report...")
    report_path = os.path.join(args.output, f"{timestamp}_report.html")
    generate_report(results, topology_path, report_path)
    console.print(f"  [green]✔[/green] Report saved → {report_path}")

    # ── Summary ──────────────────────────────────────────────────────────────
    console.print("\n")
    print_summary(results, integrity_hash)
    console.print(Panel(
        f"[green]Scan complete.[/green]\n"
        f"Report   : {report_path}\n"
        f"Raw JSON : {raw_path}\n"
        f"Topology : {topology_path}\n"
        f"SHA-256  : {integrity_hash}",
        title="[cyan]ACROPROBE — Done[/cyan]",
        border_style="green"
    ))


if __name__ == "__main__":
    if os.geteuid() != 0:
        print("[!] ACROPROBE requires root privileges for raw socket scanning.")
        print("    Run with: sudo python acroprobe.py --target <IP/CIDR>")
        sys.exit(1)
    main()
