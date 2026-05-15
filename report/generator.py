"""
ACROPROBE — Report Generator
Produces a court-ready forensic HTML report from scan results.
"""

import os
from jinja2 import Environment, FileSystemLoader


def generate_report(results: dict, topology_path: str, output_path: str):
    """
    Render the Jinja2 HTML template with scan results.
    """
    template_dir = os.path.join(os.path.dirname(__file__))
    env = Environment(loader=FileSystemLoader(template_dir))

    try:
        template = env.get_template("template.html")
    except Exception as e:
        print(f"[report] Template error: {e}")
        return

    topology_rel = os.path.relpath(topology_path, os.path.dirname(output_path))

    html = template.render(
        meta=results["meta"],
        hosts=results["hosts"],
        topology_path=topology_rel,
        total_hosts=len(results["hosts"]),
        total_ports=sum(len(d.get("open_ports", [])) for d in results["hosts"].values()),
        total_flags=sum(len(d.get("vuln_flags", [])) for d in results["hosts"].values()),
    )

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html)
