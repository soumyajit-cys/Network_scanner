Network Vulnerability Scanner 🔍

A Python-based security tool that scans local networks for active devices, open ports, and potential vulnerabilities. Perfect for network administrators and security enthusiasts to assess their network security posture.

Features 🛡️
Device Discovery: Automatically detects active devices on your local network using ARP

Port Scanning: Checks 16+ critical ports for open services (FTP, SSH, SMB, RDP, etc.)

Vulnerability Detection: Identifies common security risks:

Clear-text credential services (Telnet)

Potentially exploitable services (SMB, RDP)

Outdated software versions

Risky service configurations

Multi-threaded Scanning: Fast and efficient scanning using concurrent processing

Automated Reporting: Generates detailed security reports with severity levels

Windows Compatibility: Designed specifically for Windows environments


Requirements 📋
Windows 7 or newer

Python 3.6+

Administrator privileges (for accurate ARP scanning)

The scanner will:

1.Detect your local network configuration

2.Discover active devices using ARP

3.Scan each device for open ports

4.Check for common vulnerabilities

5.Generate a comprehensive security report



Network Security Scan Report
Generated at: [timestamp]

Scanned Devices: X
==================================================

Device: 192.168.1.1 (AA-BB-CC-DD-EE-FF)
  Open Ports:
    - 80/TCP (HTTP)
    - 443/TCP (HTTPS)
  Potential Vulnerabilities:
    - [Medium] HTTP Service: Potential web vulnerabilities (check manually)

Device: 192.168.1.15 (11-22-33-44-55-66)
  Open Ports:
    - 139/TCP (NetBIOS)
    - 445/TCP (SMB)
  Potential Vulnerabilities:
    - [High] SMB Service: Potential target for EternalBlue exploit

[Security recommendations section]



Security Recommendations 🔐
The scanner will provide actionable security advice including:

Changing default credentials

Disabling insecure services like Telnet

Securing SMB ports (139, 445)

Applying security patches

Firewall configuration tips

Limitations ⚠️
Requires administrator privileges for full functionality

Scans only the local subnet

Basic vulnerability checks (not a replacement for professional tools)

May trigger security alerts on monitored networks

Important: Always obtain proper authorization before scanning networks you don't own.

Contributing 🤝
Contributions are welcome! Please follow these steps:

Fork the repository

Create your feature branch (git checkout -b feature/your-feature)

Commit your changes (git commit -am 'Add some feature')

Push to the branch (git push origin feature/your-feature)

Open a pull request






























