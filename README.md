# 🔍 Network Vulnerability Scanner

A lightweight, cross-platform network vulnerability scanner written in a single Python file. No external dependencies. No configuration. Just run it.

---

## Features

- **Auto-detects** your local IP and subnet — no manual config needed
- **Host discovery** via ping sweep with TCP fallback for firewalled hosts
- **Threaded port scanning** across 47 common ports for fast results
- **Banner grabbing** to fingerprint running services
- **Risk-rated output** — every open port is classified as INFO / LOW / MEDIUM / HIGH / CRITICAL
- **Inline advisories** with remediation guidance for dangerous ports
- **Coloured terminal output** (auto-disabled on unsupported terminals)
- **Summary report** of top findings ranked by severity

---

## Requirements

- Python 3.6 or higher
- No third-party packages — uses only the standard library (`socket`, `subprocess`, `threading`, `ipaddress`, `platform`, `concurrent.futures`)

---

## Quick Start

```bash
python scanner.py
```

That's it. The scanner will detect your network and begin scanning automatically.

---

## Usage

```
python scanner.py [OPTIONS]
```

| Option | Short | Default | Description |
|---|---|---|---|
| `--target` | `-t` | Auto-detect `/24` | CIDR range or single IP to scan |
| `--ports` | `-p` | Built-in list (47 ports) | Comma-separated list of ports |
| `--threads` | `-T` | `100` | Threads for host discovery |
| `--port-threads` | | `60` | Threads per host during port scan |
| `--timeout` | `-w` | `0.5` | Socket timeout in seconds |
| `--no-color` | | Off | Disable ANSI colour output |
| `--skip-discovery` | | Off | Skip ping sweep, scan target directly |

### Examples

```bash
# Auto-detect and scan the whole local network
python scanner.py

# Scan a specific subnet
python scanner.py --target 192.168.1.0/24

# Scan a single host
python scanner.py --target 192.168.1.10

# Scan only specific ports
python scanner.py --ports 22,80,443,3306,3389

# Faster scan — more threads, shorter timeout
python scanner.py --threads 150 --port-threads 80 --timeout 0.3

# Skip discovery (useful when ICMP is blocked network-wide)
python scanner.py --target 10.0.0.50 --skip-discovery

# No colour (useful for logging to a file)
python scanner.py --no-color > report.txt
```

---

## Sample Output

```
════════════════════════════════════════════════════════════════════════
                   NETWORK VULNERABILITY SCANNER  v1.0
  Scan started: 2024-11-12  14:22:01
════════════════════════════════════════════════════════════════════════

  ◉  LOCAL IP   : 192.168.1.42
  ◉  NETWORK    : 192.168.1.0/24

  [1/2]  DISCOVERING HOSTS on 192.168.1.0/24  (254 addresses)...

  Found 6 live host(s) in 4.3s

  [2/2]  PORT SCANNING  (47 ports × 6 host(s))

────────────────────────────────────────────────────────────────────────
  HOST: 192.168.1.1  (router.local)   [ CRITICAL ]
────────────────────────────────────────────────────────────────────────
  PORT   SERVICE           RISK         BANNER / NOTE
────────────────────────────────────────────────────────────────────────
  23     Telnet            CRITICAL     Plaintext remote shell – REPLACE WITH SSH
     ⚠  Plaintext remote shell – REPLACE WITH SSH IMMEDIATELY
  80     HTTP              MEDIUM       HTTP/1.0 200 OK
  443    HTTPS             INFO         Encrypted web – verify certificate validity

════════════════════════════════════════════════════════════════════════
  SCAN SUMMARY
════════════════════════════════════════════════════════════════════════

  Hosts scanned    : 6
  Open ports found : 14
  CRITICAL issues  : 2
  HIGH risk ports  : 3

  Elapsed time     : 18.4s
```

---

## Risk Levels

| Level | Colour | Meaning |
|---|---|---|
| **INFO** | Blue | Open but generally safe (e.g. HTTPS) |
| **LOW** | Green | Low risk — keep patched (e.g. SSH) |
| **MEDIUM** | Yellow | Moderate concern — review configuration (e.g. HTTP) |
| **HIGH** | Orange | Significant risk — restrict access (e.g. SMB, MySQL) |
| **CRITICAL** | Red | Immediate action required — close or remediate now |

### Ports flagged CRITICAL

| Port | Service | Why |
|---|---|---|
| 23 | Telnet | Credentials sent in plaintext |
| 445 | SMB | EternalBlue / WannaCry attack surface |
| 3389 | RDP | Frequent brute-force and exploit target |
| 4444 | Metasploit | Default reverse shell listener — highly suspicious |
| 5900 | VNC | Often runs with weak or no authentication |
| 2375 | Docker | Unauthenticated Docker daemon = full host takeover |
| 6379 | Redis | Frequently exposed without authentication |
| 9200 | Elasticsearch | Frequently exposed without authentication |
| 27017 | MongoDB | Frequently exposed without authentication |

---

## How It Works

```
┌─────────────────────────────────────────────────────┐
│  1. Network Detection                               │
│     UDP socket trick → local IP → /24 CIDR range   │
├─────────────────────────────────────────────────────┤
│  2. Host Discovery (parallel)                       │
│     OS ping command per host (100 threads)          │
│     TCP fallback on ports 22/80/443/445             │
├─────────────────────────────────────────────────────┤
│  3. Port Scanning (per host, parallel)              │
│     TCP connect to each port (60 threads)           │
├─────────────────────────────────────────────────────┤
│  4. Banner Grabbing                                 │
│     HTTP HEAD request or raw \r\n probe             │
│     First 120 chars of response captured            │
├─────────────────────────────────────────────────────┤
│  5. Risk Rating & Reporting                         │
│     Lookup against built-in port database           │
│     Per-host results + final summary                │
└─────────────────────────────────────────────────────┘
```

---

## Limitations

- **ICMP may require elevated privileges** on some systems (especially Linux). Run with `sudo` if host discovery returns no results, or use `--skip-discovery`.
- **Not a replacement for Nmap.** This tool is designed for quick, dependency-free assessments. For comprehensive audits use a dedicated scanner.
- **TCP only.** UDP services (DNS, SNMP, DHCP, etc.) will not be detected via port scan, though they are flagged if a TCP port in the same range is found open.
- **No CVE lookup.** Risk ratings are based on port/service classification, not live vulnerability databases.

---

## Legal Notice

> **Only scan networks and systems you own or have explicit written permission to test.**  
> Unauthorised port scanning may be illegal in your jurisdiction and violates most network terms of service.  
> The authors accept no liability for misuse of this tool.

---

## License

MIT — free to use, modify, and distribute.






























