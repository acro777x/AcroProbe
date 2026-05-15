"""
ACROPROBE — Module: Network Topology Builder
Generates an interactive HTML graph using pyvis.
"""

from pyvis.network import Network


def build_topology(hosts: dict, output_path: str):
    """
    Build an interactive network topology map.
    Red nodes = hosts with vulnerability flags.
    Green nodes = clean hosts.
    Blue node = gateway/router (assumed .1).
    """
    net = Network(
        height="600px",
        width="100%",
        bgcolor="#0d1117",
        font_color="white",
        directed=False
    )
    net.barnes_hut()

    # Add central gateway node
    gateway = None
    for ip in hosts:
        parts = ip.split(".")
        candidate = ".".join(parts[:3]) + ".1"
        gateway = candidate
        break

    if gateway:
        net.add_node(
            gateway,
            label=f"Gateway\n{gateway}",
            color="#00aaff",
            size=30,
            shape="diamond"
        )

    for ip, data in hosts.items():
        has_flags = bool(data.get("vuln_flags"))
        open_count = len(data.get("open_ports", []))
        os_info = data.get("os", "Unknown")

        color = "#ff4444" if has_flags else "#44ff88"
        title = (
            f"<b>{ip}</b><br>"
            f"OS: {os_info}<br>"
            f"Open Ports: {open_count}<br>"
            f"Flags: {len(data.get('vuln_flags', []))}"
        )

        net.add_node(
            ip,
            label=f"{ip}\n({open_count} ports)",
            color=color,
            size=20,
            title=title
        )

        if gateway and ip != gateway:
            net.add_edge(gateway, ip, color="#444444")

    net.set_options("""
    {
      "physics": {
        "forceAtlas2Based": {
          "gravitationalConstant": -50,
          "centralGravity": 0.01,
          "springLength": 150
        },
        "solver": "forceAtlas2Based"
      }
    }
    """)

    net.save_graph(output_path)
