#!/usr/bin/env python3
"""
Home Network Security Scanner
-----------------------------
Discovers devices on your local network, scans them for open ports,
and flags common security risks (insecure services, unexpected open ports).

IMPORTANT: Only run this against networks you own or have explicit
permission to test (e.g. your own home Wi-Fi). Scanning networks you
don't have permission for is illegal in most jurisdictions.
"""

import nmap
import sys
from datetime import datetime

RISKY_PORTS = {
    21:   "FTP - often unencrypted, credentials sent in plain text",
    23:   "Telnet - unencrypted remote access, should be disabled",
    135:  "MS RPC - common target for lateral movement attacks",
    139:  "NetBIOS - legacy file sharing, often unnecessary exposure",
    445:  "SMB - frequent target for ransomware (e.g. WannaCry)",
    3389: "RDP - remote desktop, high-value target if exposed without MFA/VPN",
    5900: "VNC - remote access, often runs with weak/no authentication",
}


def discover_hosts(network_range):
    scanner = nmap.PortScanner()
    print(f"[*] Discovering devices on {network_range} ...")
    scanner.scan(hosts=network_range, arguments="-sn")
    live_hosts = scanner.all_hosts()
    print(f"[*] Found {len(live_hosts)} device(s)\n")
    return live_hosts


def scan_ports(ip):
    scanner = nmap.PortScanner()
    ports_to_check = ",".join(str(p) for p in RISKY_PORTS.keys())
    common_ports = "22,80,443,8080"
    port_list = f"{ports_to_check},{common_ports}"

    scanner.scan(ip, arguments=f"-p {port_list} -sV -T4")

    open_ports = {}
    if ip in scanner.all_hosts():
        for proto in scanner[ip].all_protocols():
            for port, data in scanner[ip][proto].items():
                if data["state"] == "open":
                    product = data.get("product", "")
                    version = data.get("version", "")
                    version_str = f"{product} {version}".strip()
                    open_ports[port] = {
                        "name": data.get("name", "unknown"),
                        "version": version_str if version_str else None,
                    }

    return open_ports


def build_report(hosts):
    report = []

    for ip in hosts:
        print(f"[*] Scanning ports on {ip} ...")
        open_ports = scan_ports(ip)

        findings = []
        for port, info in open_ports.items():
            service = info["name"]
            version = info["version"]

            if port in RISKY_PORTS:
                findings.append({
                    "port": port,
                    "service": service,
                    "version": version,
                    "risk": "HIGH",
                    "reason": RISKY_PORTS[port],
                })
            else:
                findings.append({
                    "port": port,
                    "service": service,
                    "version": version,
                    "risk": "INFO",
                    "reason": "Common service, not inherently risky",
                })

        report.append({"ip": ip, "findings": findings})

    return report


def build_report_text(report):
    lines = []
    total_high_risk = 0
    total_open_ports = 0
    hosts_with_findings = 0

    for entry in report:
        findings = entry["findings"]
        if findings:
            hosts_with_findings += 1
        for f in findings:
            total_open_ports += 1
            if f["risk"] == "HIGH":
                total_high_risk += 1

    lines.append("=" * 60)
    lines.append("  NETWORK SECURITY SCAN REPORT")
    lines.append(f"  Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append("=" * 60)
    lines.append("")
    lines.append("SUMMARY")
    lines.append(f"  Hosts scanned:        {len(report)}")
    lines.append(f"  Hosts with open ports: {hosts_with_findings}")
    lines.append(f"  Total open ports:      {total_open_ports}")
    lines.append(f"  High-risk findings:    {total_high_risk}")
    lines.append("")
    lines.append("DETAILS")

    for entry in report:
        ip = entry["ip"]
        findings = entry["findings"]

        lines.append(f"\nHost: {ip}")
        if not findings:
            lines.append("  No open ports found in scanned range.")
            continue

        for f in findings:
            marker = "[HIGH RISK]" if f["risk"] == "HIGH" else "[INFO]     "
            version_info = f" - {f['version']}" if f.get("version") else ""
            lines.append(f"  {marker} Port {f['port']} ({f['service']}{version_info}) - {f['reason']}")

    lines.append("\n" + "-" * 60)
    lines.append(f"Summary: {total_high_risk} high-risk finding(s) across {len(report)} host(s)")
    lines.append("-" * 60)

    return "\n".join(lines)


def save_report(report_text):
    filename = f"scan_report_{datetime.now().strftime('%Y-%m-%d_%H%M%S')}.txt"
    with open(filename, "w") as f:
        f.write(report_text)
    print(f"\n[*] Report saved to: {filename}")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 scanner.py <network_range>")
        print("Example: python3 scanner.py 192.168.1.0/24")
        sys.exit(1)

    network_range = sys.argv[1]
    hosts = discover_hosts(network_range)
    report = build_report(hosts)

    report_text = build_report_text(report)
    print("\n" + report_text)
    save_report(report_text)
