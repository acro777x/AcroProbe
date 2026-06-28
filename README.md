# 🔍 ACROPROBE — Network Reconnaissance & Forensic Threat Mapper

<div align="center">

```
 █████╗  ██████╗██████╗  ██████╗ ██████╗ ██████╗  ██████╗ ██████╗ ███████╗
██╔══██╗██╔════╝██╔══██╗██╔═══██╗██╔══██╗██╔══██╗██╔═══██╗██╔══██╗██╔════╝
███████║██║     ██████╔╝██║   ██║██████╔╝██████╔╝██║   ██║██████╔╝█████╗  
██╔══██║██║     ██╔══██╗██║   ██║██╔═══╝ ██╔══██╗██║   ██║██╔══██╗██╔══╝  
██║  ██║╚██████╗██║  ██║╚██████╔╝██║     ██║  ██║╚██████╔╝██████╔╝███████╗
╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝ ╚═════╝ ╚═╝     ╚═╝  ╚═╝ ╚═════╝ ╚═════╝ ╚══════╝
```


**Part of the Acro Tool Suite | Companion to [ACROMAP](https://github.com/acro777x/acromap)**

![Python](https://img.shields.io/badge/Python-3.8+-blue?style=flat-square&logo=python)
![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Kali-darkgreen?style=flat-square)
![License](https://img.shields.io/badge/License-MIT-orange?style=flat-square)
![Status](https://img.shields.io/badge/Status-Active%20Development-red?style=flat-square)
![Authorized Use Only](https://img.shields.io/badge/Use-Authorized%20Only-critical?style=flat-square)

</div>

---

## What is ACROPROBE?

ACROPROBE is a **network reconnaissance and forensic threat mapping tool** designed for authorized network investigations. It scans a target network, discovers all active devices, maps their open ports and running services, detects potential vulnerabilities, and compiles everything into a **structured, investigator-friendly HTML report** — ready to be attached directly to a forensic case file without any manual interpretation of raw scanner output.

Most network scanners dump raw data that only a trained analyst can read. ACROPROBE is built for real investigation workflows — where the end user might be a law enforcement officer, a forensic examiner, or a security auditor who needs **clear, timestamped, hash-verified findings**, not terminal output.

> **Part of the Acro Suite:** ACROMAP finds vulnerabilities through deep penetration testing. ACROPROBE maps the network and documents it for forensic use. Two tools, one investigation pipeline.

---

## 🧠 Core Capabilities

| Module | What It Does |
|---|---|
| **Host Discovery** | Scans target IP range using ARP + ICMP to find all live hosts |
| **Port Scanning** | TCP SYN scan on common + extended port ranges per host |
| **Service Fingerprinting** | Identifies running service name, version, and banner for each open port |
| **OS Detection** | TTL-based and Nmap OS detection for each discovered host |
| **Vulnerability Flags** | Cross-references open services against a local CVE pattern list |
| **Network Topology Map** | Visual graph of all hosts and their connections |
| **Forensic Report Generator** | HTML report with SHA-256 integrity hash, examiner info, and timestamps |
| **Evidence Chain of Custody** | Each scan session is sealed with a hash — any post-scan modification is detectable |

---

## 🗂️ Acro Tool Suite

```
Acro Suite
├── ACROMAP   →  32-phase automated VAPT framework (github.com/acro777x/acromap)
├── ACROPROBE →  Network recon + forensic threat mapper         [YOU ARE HERE]
├── ACROVAULT →  WhatsApp evidence extraction & preservation    [Coming Soon]
└── ACROTRACE →  UPI fraud transaction graph analyzer           [Coming Soon]
```

Each tool is independent but designed to work as a pipeline:
**Find vulnerabilities → Map the network → Preserve chat evidence → Follow the money**

---

## ⚙️ Tech Stack

```
Language    : Python 3.8+
Scanning    : python-nmap (Nmap wrapper), scapy (ARP discovery)
Reporting   : Jinja2 (HTML templating), hashlib (SHA-256 integrity)
Graphs      : networkx + pyvis (interactive topology map)
Output      : HTML report + JSON raw data dump
OS          : Kali Linux / Ubuntu (tested)
```

---

## 📁 Project Structure

```
acroprobe/
│
├── acroprobe.py          # Main entry point
├── requirements.txt      # Python dependencies
│
├── modules/
│   ├── discovery.py      # Host discovery (ARP + ICMP)
│   ├── portscan.py       # Port scanning + service fingerprinting
│   ├── osdetect.py       # OS detection module
│   ├── vulncheck.py      # CVE pattern matching against open services
│   └── topology.py       # Network graph builder (pyvis)
│
├── report/
│   ├── generator.py      # HTML report builder
│   └── template.html     # Jinja2 report template
│
├── output/               # All scan results saved here
│   ├── [timestamp]_report.html
│   └── [timestamp]_raw.json
│
└── README.md
```

---

## 🚀 Installation

```bash
# Clone the repository
git clone https://github.com/acro777x/acroprobe.git
cd acroprobe

# Install dependencies
pip install -r requirements.txt

# Nmap must be installed on the system
sudo apt install nmap -y
```

---

## 🖥️ Usage

```bash
# Basic scan of a single IP
sudo python acroprobe.py --target 192.168.1.1

# Scan entire subnet
sudo python acroprobe.py --target 192.168.1.0/24

# Full scan with OS detection and vulnerability check
sudo python acroprobe.py --target 192.168.1.0/24 --full

# Specify output folder
sudo python acroprobe.py --target 192.168.1.0/24 --output /cases/case_2026_001/

# Add examiner name to report (for forensic use)
sudo python acroprobe.py --target 192.168.1.0/24 --examiner "ACRO" --case "OFC-SEC-2026-01"
```

---

## 📄 Report Output

Every scan generates two files in the `/output` directory:

**1. `[timestamp]_report.html`** — The main forensic report containing:
- Case metadata (examiner name, date, time, target)
- SHA-256 integrity hash of the raw scan data
- List of all discovered hosts with MAC address, IP, hostname
- Per-host breakdown: open ports, services, versions, banners
- Vulnerability flags with severity labels
- Interactive network topology map
- Footer hash for chain-of-custody verification

**2. `[timestamp]_raw.json`** — Machine-readable raw scan data for further processing or ingestion into SIEM tools.

### Sample Report Structure
```
┌─────────────────────────────────────────────┐
│         ACROPROBE FORENSIC REPORT           │
│  Case ID   : OFC-SEC-2026-01                │
│  Examiner  : ACRO                           │
│  Scan Date : 2026-05-14 | 11:42:03 IST      │
│  Target    : 192.168.1.0/24                 │
│  Integrity : SHA-256: a3f1c9...             │
├─────────────────────────────────────────────┤
│  Hosts Discovered : 14                      │
│  Open Ports Found : 87                      │
│  Vulnerability Flags : 6                    │
└─────────────────────────────────────────────┘

HOST: 192.168.1.5
  MAC     : A4:C3:F0:85:AC:B1
  OS      : Windows 10 (TTL 128)
  Ports   :
    80/tcp   OPEN   Apache httpd 2.4.41
    445/tcp  OPEN   Microsoft-DS (SMB)
    3389/tcp OPEN   MS-WBT-Server (RDP)
  Flags   :
    ⚠ SMB open — check MS17-010 (EternalBlue)
    ⚠ RDP exposed — brute-force risk
```

---

## 🔐 Forensic Design Principles

ACROPROBE is built with forensic integrity in mind:

- **No data modification** — read-only network observation, nothing is written to target systems
- **Timestamped sessions** — every scan has a precise start and end time in IST
- **SHA-256 integrity seal** — raw output is hashed before report generation; hash is embedded in report footer
- **Examiner attribution** — examiner name and case ID are embedded in every report
- **Structured output** — reports are formatted for direct inclusion in legal/forensic documentation

---

## ⚠️ Legal Disclaimer

ACROPROBE is intended **solely** for:
- Authorized network security assessments on systems you own or have **explicit written permission** to test
- Academic research and CTF/lab environments
- Forensic investigations conducted under proper legal authority

Unauthorized use is illegal under the **IT Act 2000 (India)**, Computer Fraud and Abuse Act (CFAA), and equivalent laws worldwide. The author bears no responsibility for illegal or malicious use. By using this tool you accept full legal responsibility for your actions.

---

## 👤 Author

**ACRO**
 github.com/acro777x

> *"Scan smarter. Document everything. Leave no ambiguity."*

---

## 🔗 Related Projects

- [ACROMAP](https://github.com/acro777x/acromap) — 32-Phase Automated VAPT Framework
- ACROVAULT — WhatsApp Evidence Preservation Tool *(coming soon)*
- ACROTRACE — UPI Fraud Transaction Graph Analyzer *(coming soon)*
