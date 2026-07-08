# Home Network Security Scanner

A Python command-line tool that discovers devices on a local network, scans them for open ports, identifies running services/versions, and flags common security risks — with results printed to the terminal and saved to a timestamped report file.


## What it does

1. **Device discovery** — pings a given network range (e.g. `192.168.1.0/24`) to find live devices.
2. **Port scanning** — checks each discovered device for a defined set of ports, including both common services (SSH, HTTP, HTTPS) and commonly-risky legacy services (FTP, Telnet, SMB, RDP, VNC, NetBIOS, MS RPC).
3. **Service/version detection** — uses nmap's version detection (`-sV`) to identify not just that a port is open, but what software is running on it.
4. **Risk flagging** — cross-references open ports against a small, curated list of services commonly flagged in security hardening guidance (loosely informed by frameworks like the ACSC Essential Eight and CIS Benchmarks), and marks each finding as `HIGH RISK` or `INFO`.
5. **Reporting** — prints a summary (hosts scanned, open ports found, high-risk count) followed by per-host details, and saves the same report to a timestamped `.txt` file for record-keeping.

## Tech stack

- Python 3
- [python-nmap](https://pypi.org/project/python-nmap/) (wrapper around the nmap CLI tool)
- nmap (underlying scan engine)

## Usage

\`\`\`bash
python3 -m venv venv
source venv/bin/activate
pip install python-nmap
sudo venv/bin/python3 scanner.py 192.168.1.0/24
\`\`\`

Replace `192.168.1.0/24` with your own network's range (find it via `ifconfig` on Mac/Linux or `ipconfig` on Windows).

`sudo` is required because the underlying ping scan needs elevated network permissions.

## Important — responsible use

This tool is intended to be run **only against networks you own or have explicit permission to test**, such as your own home network. Scanning networks without authorization is illegal in most jurisdictions and against the ethical principles of security testing. All development and testing for this project was carried out exclusively on my own home network.

## Design notes / limitations

- Only a curated set of ports is scanned (not the full 65535) to keep scans fast and focused on genuinely common risk indicators.
- Risk flagging is intentionally simple (a lookup table of known-risky ports), not a full vulnerability scanner — this was a deliberate scope decision to keep the tool understandable and maintainable rather than attempting broad CVE coverage.
- Version detection depends on nmap's ability to fingerprint a service; some devices may not return detailed version info depending on their configuration.

## Possible future improvements

- CSV/JSON export alongside the plain text report
- Scheduled/recurring scans with historical comparison
- Integration with a public CVE database for version-specific vulnerability lookups
