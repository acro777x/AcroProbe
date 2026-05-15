# ACROPROBE — Changelog

## [v1.0.0] — May 2026 — Initial Release

### Added
- Host discovery via ARP sweep (Scapy) with nmap ping fallback
- Port scanning with service fingerprinting (common / extended / all modes)
- TTL-based OS detection with nmap -O confirmation
- Vulnerability flag checker — 16 risky service/port patterns
- Interactive network topology map (pyvis)
- Forensic HTML report with SHA-256 chain of custody seal
- Raw JSON export for SIEM ingestion
- Rich terminal output with phase-by-phase progress
- Examiner name and Case ID embedding in all reports
- Root privilege check on startup

### Coming Next (v1.1)
- ACROVAULT integration — attach WhatsApp evidence report to same case
- CVE API lookup for detected service versions
- PDF export of forensic report
- Multi-target batch scanning mode
