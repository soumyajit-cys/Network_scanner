
    #!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════╗
║           NETWORK VULNERABILITY SCANNER v1.0                    ║
║     Cross-platform | Threaded | Auto-detect | Risk-rated        ║
╚══════════════════════════════════════════════════════════════════╝

Usage:
    python scanner.py                  # Auto-detect network and scan
    python scanner.py --target 192.168.1.0/24
    python scanner.py --target 192.168.1.10
    python scanner.py --ports 22,80,443,3389
    python scanner.py --threads 100
    python scanner.py --timeout 0.5
    python scanner.py --no-color
"""

import argparse
import ipaddress
import platform
import queue
import socket
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

# ──────────────────────────────────────────────
# ANSI COLOR CODES  (auto-disabled on Windows or --no-color)
# ──────────────────────────────────────────────

def _supports_color():
    """Return True if the terminal supports ANSI colours."""
    if platform.system() == "Windows":
        try:
            import ctypes
            kernel32 = ctypes.windll.kernel32          # type: ignore[attr-defined]
            # Enable VIRTUAL_TERMINAL_PROCESSING on Windows 10+
            kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)
            return True
        except Exception:
            return False
    return hasattr(sys.stdout, "isatty") and sys.stdout.isatty()

USE_COLOR = _supports_color()

class C:
    """Terminal colour helpers."""
    RESET   = "\033[0m"
    BOLD    = "\033[1m"
    RED     = "\033[91m"
    ORANGE  = "\033[93m"
    YELLOW  = "\033[33m"
    GREEN   = "\033[92m"
    CYAN    = "\033[96m"
    BLUE    = "\033[94m"
    MAGENTA = "\033[95m"
    GREY    = "\033[90m"
    WHITE   = "\033[97m"

    @staticmethod
    def disable():
        for attr in ["RESET","BOLD","RED","ORANGE","YELLOW","GREEN",
                     "CYAN","BLUE","MAGENTA","GREY","WHITE"]:
            setattr(C, attr, "")

def col(text, *codes):
    return "".join(codes) + text + C.RESET if USE_COLOR else text

# ──────────────────────────────────────────────
# KNOWN PORTS  –  service name + risk level
# ──────────────────────────────────────────────
# Risk: 0 = info, 1 = low, 2 = medium, 3 = high, 4 = critical

PORT_DB = {
    20:   ("FTP-Data",          2, "Unencrypted file transfer data channel"),
    21:   ("FTP",               3, "Unencrypted file transfer – credentials sent in plaintext"),
    22:   ("SSH",               1, "Encrypted remote shell – keep patched & disable root login"),
    23:   ("Telnet",            4, "Plaintext remote shell – REPLACE WITH SSH IMMEDIATELY"),
    25:   ("SMTP",              2, "Mail relay – check for open relay misconfiguration"),
    53:   ("DNS",               1, "DNS – check for open resolver / zone-transfer exposure"),
    67:   ("DHCP",              1, "DHCP server – rogue DHCP risk if unexpected"),
    69:   ("TFTP",              3, "Trivial FTP – no authentication, unencrypted"),
    80:   ("HTTP",              2, "Unencrypted web – consider enforcing HTTPS redirect"),
    110:  ("POP3",              3, "Unencrypted email retrieval – credentials in plaintext"),
    111:  ("RPC",               3, "RPC portmapper – frequently exploited"),
    119:  ("NNTP",              2, "News protocol – rarely needed, close if unused"),
    123:  ("NTP",               1, "Time sync – check for amplification DDoS config"),
    135:  ("MSRPC",             3, "Windows RPC – attack surface for many Windows exploits"),
    137:  ("NetBIOS-NS",        3, "NetBIOS Name Service – leaks host info"),
    138:  ("NetBIOS-DGM",       3, "NetBIOS Datagram – leaks host info"),
    139:  ("NetBIOS-SSN",       3, "NetBIOS Session – legacy SMB, disable if possible"),
    143:  ("IMAP",              3, "Unencrypted email – credentials in plaintext"),
    161:  ("SNMP",              3, "SNMP – default community strings leak full device info"),
    389:  ("LDAP",              3, "Unencrypted LDAP – use LDAPS (636) instead"),
    443:  ("HTTPS",             0, "Encrypted web – verify certificate validity"),
    445:  ("SMB",               4, "SMB – EternalBlue / WannaCry attack vector, patch urgently"),
    465:  ("SMTPS",             1, "Encrypted SMTP submission"),
    500:  ("IKE/VPN",           1, "VPN endpoint – check for weak cipher suites"),
    514:  ("Syslog",            2, "UDP Syslog – log data sent unencrypted"),
    587:  ("SMTP-Submit",       1, "Mail submission – ensure authentication required"),
    631:  ("IPP/CUPS",          2, "Printing service – check for unauthenticated access"),
    636:  ("LDAPS",             1, "Encrypted LDAP"),
    993:  ("IMAPS",             1, "Encrypted IMAP"),
    995:  ("POP3S",             1, "Encrypted POP3"),
    1080: ("SOCKS Proxy",       3, "Open proxy – could be used for traffic tunnelling"),
    1433: ("MSSQL",             3, "Microsoft SQL Server – direct DB exposure is high risk"),
    1521: ("Oracle DB",         3, "Oracle database – direct DB exposure is high risk"),
    2049: ("NFS",               3, "Network File System – often misconfigured world-readable"),
    2375: ("Docker",            4, "Docker daemon (unencrypted) – full host takeover risk"),
    2376: ("Docker-TLS",        2, "Docker daemon (TLS) – verify certificate pinning"),
    3000: ("Dev Server",        2, "Common dev server port – should not be internet-facing"),
    3306: ("MySQL",             3, "MySQL – direct DB exposure is high risk"),
    3389: ("RDP",               4, "Remote Desktop – frequent brute-force/exploit target"),
    4444: ("Metasploit",        4, "Default Metasploit listener – highly suspicious"),
    5432: ("PostgreSQL",        3, "PostgreSQL – direct DB exposure is high risk"),
    5900: ("VNC",               4, "VNC – often uses weak/no auth, full desktop access"),
    5985: ("WinRM-HTTP",        3, "Windows Remote Management (unencrypted)"),
    5986: ("WinRM-HTTPS",       2, "Windows Remote Management (TLS)"),
    6379: ("Redis",             4, "Redis – frequently exposed without auth, full RCE risk"),
    8080: ("HTTP-Alt",          2, "Alternate HTTP – check for proxy/admin panel exposure"),
    8443: ("HTTPS-Alt",         1, "Alternate HTTPS"),
    8888: ("Jupyter/Dev",       3, "Jupyter Notebook / dev server – check for auth"),
    9200: ("Elasticsearch",     4, "Elasticsearch – frequently exposed without auth"),
    27017:("MongoDB",           4, "MongoDB – frequently exposed without auth, full data leak"),
}

RISK_LABELS = {
    0: col("  INFO    ", C.BLUE,  C.BOLD),
    1: col("  LOW     ", C.GREEN, C.BOLD),
    2: col("  MEDIUM  ", C.YELLOW,C.BOLD),
    3: col("  HIGH    ", C.ORANGE,C.BOLD),
    4: col(" CRITICAL ", C.RED,   C.BOLD),
}

RISK_COLORS = {
    0: C.BLUE,
    1: C.GREEN,
    2: C.YELLOW,
    3: C.ORANGE,
    4: C.RED,
}

# Default ports to scan (union of well-known + common attack surface)
DEFAULT_PORTS = sorted(PORT_DB.keys())

# ──────────────────────────────────────────────
# NETWORK DETECTION
# ──────────────────────────────────────────────

def get_local_ip():
    """
    Reliably determine the host's primary LAN IP by opening a UDP socket
    toward an external address (no data is actually sent).
    Falls back to gethostbyname if the UDP trick fails.
    """
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(2)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        try:
            return socket.gethostbyname(socket.gethostname())
        except Exception:
            return "127.0.0.1"

def get_network_range(ip: str, prefix_len: int = 24) -> str:
    """Convert a host IP to its /24 CIDR network string."""
    net = ipaddress.IPv4Network(f"{ip}/{prefix_len}", strict=False)
    return str(net)

def get_hostname(ip: str) -> str:
    """Reverse-resolve IP to hostname; return empty string on failure."""
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return ""

# ──────────────────────────────────────────────
# HOST DISCOVERY  (ping sweep)
# ──────────────────────────────────────────────

def ping_host(ip: str, timeout: float = 1.0) -> bool:
    """
    Send one ICMP ping.  Works on all platforms via the OS ping command.
    Returns True if host responds.
    """
    system = platform.system().lower()
    if system == "windows":
        cmd = ["ping", "-n", "1", "-w", str(int(timeout * 1000)), ip]
    else:
        cmd = ["ping", "-c", "1", "-W", str(int(timeout)), ip]

    try:
        result = subprocess.run(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=timeout + 1,
        )
        return result.returncode == 0
    except Exception:
        return False

def tcp_probe(ip: str, port: int = 80, timeout: float = 0.5) -> bool:
    """
    Lightweight TCP connect probe as a fallback when ICMP is blocked.
    Returns True if the connection succeeds.
    """
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except Exception:
        return False

def discover_hosts(network: str, timeout: float = 1.0,
                   max_workers: int = 100,
                   progress_cb=None) -> list:
    """
    Perform a parallel ping sweep across all hosts in *network*.
    Falls back to TCP probes on common ports for firewalled hosts.
    Returns a sorted list of live IP strings.
    """
    net = ipaddress.IPv4Network(network, strict=False)
    hosts = list(net.hosts())
    total = len(hosts)
    live = []
    lock = threading.Lock()
    counter = [0]

    def probe(ip_obj):
        ip = str(ip_obj)
        alive = ping_host(ip, timeout)
        if not alive:
            # Try TCP fallback on a handful of ports
            for p in (80, 443, 22, 445):
                if tcp_probe(ip, p, timeout / 2):
                    alive = True
                    break
        with lock:
            counter[0] += 1
            if progress_cb:
                progress_cb(counter[0], total)
        if alive:
            return ip
        return None

    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        futures = {ex.submit(probe, h): h for h in hosts}
        for f in as_completed(futures):
            res = f.result()
            if res:
                live.append(res)

    return sorted(live, key=lambda x: ipaddress.IPv4Address(x))

# ──────────────────────────────────────────────
# PORT SCANNING
# ──────────────────────────────────────────────

def scan_port(ip: str, port: int, timeout: float = 0.5) -> bool:
    """Attempt a TCP connect to ip:port; return True if open."""
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except Exception:
        return False

def grab_banner(ip: str, port: int, timeout: float = 2.0) -> str:
    """
    Try to read a service banner from an open port.
    Sends a generic HTTP request for port 80/8080/8443 variants,
    a plain newline for everything else.
    """
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((ip, port))

        if port in (80, 8080, 8000, 8888):
            s.sendall(b"HEAD / HTTP/1.0\r\nHost: " + ip.encode() + b"\r\n\r\n")
        elif port == 443:
            s.close()
            return ""          # TLS – skip plaintext banner
        else:
            s.sendall(b"\r\n")

        banner = s.recv(1024).decode("utf-8", errors="replace").strip()
        s.close()

        # Clean up – take only the first meaningful line
        first_line = banner.splitlines()[0][:120] if banner else ""
        return first_line
    except Exception:
        return ""

def scan_host_ports(ip: str, ports: list, timeout: float = 0.5,
                    max_workers: int = 50) -> list:
    """
    Scan *ports* on *ip* concurrently.
    Returns a list of dicts for every open port.
    """
    open_ports = []
    lock = threading.Lock()

    def check(port):
        if scan_port(ip, port, timeout):
            info = PORT_DB.get(port, ("Unknown", 1, "No additional info"))
            service, risk, note = info
            banner = grab_banner(ip, port, timeout * 3)
            with lock:
                open_ports.append({
                    "port":    port,
                    "service": service,
                    "risk":    risk,
                    "note":    note,
                    "banner":  banner,
                })

    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        list(as_completed({ex.submit(check, p): p for p in ports}))

    return sorted(open_ports, key=lambda x: x["port"])

# ──────────────────────────────────────────────
# DISPLAY HELPERS
# ──────────────────────────────────────────────

WIDTH = 72

def banner_line(char="═"):
    return col(char * WIDTH, C.CYAN)

def section_line(char="─"):
    return col(char * WIDTH, C.GREY)

def print_header():
    print()
    print(banner_line("═"))
    title = "  NETWORK VULNERABILITY SCANNER  v1.0"
    pad   = (WIDTH - len(title)) // 2
    print(col(" " * pad + title, C.CYAN, C.BOLD))
    ts = datetime.now().strftime("%Y-%m-%d  %H:%M:%S")
    sub = f"  Scan started: {ts}"
    print(col(sub, C.GREY))
    print(banner_line("═"))

def print_network_info(local_ip, network):
    print()
    print(col("  ◉  LOCAL IP   : ", C.BOLD) + col(local_ip, C.WHITE, C.BOLD))
    print(col("  ◉  NETWORK    : ", C.BOLD) + col(network,  C.WHITE, C.BOLD))
    print()

def progress_bar(done: int, total: int, width: int = 40, label: str = ""):
    """Print an in-place progress bar."""
    pct   = done / total if total else 1
    filled = int(width * pct)
    bar   = "█" * filled + "░" * (width - filled)
    line  = f"\r  {label} [{bar}] {done}/{total} "
    sys.stdout.write(col(line, C.CYAN))
    sys.stdout.flush()

def print_host_result(ip: str, hostname: str, open_ports: list):
    """Print the full result block for one host."""
    print()
    print(banner_line("─"))

    host_display = col(ip, C.WHITE, C.BOLD)
    if hostname:
        host_display += col(f"  ({hostname})", C.GREY)

    max_risk = max((p["risk"] for p in open_ports), default=0) if open_ports else 0
    risk_badge = f"[{RISK_LABELS[max_risk]}]"

    print(f"  HOST: {host_display}   {risk_badge}")
    print(section_line())

    if not open_ports:
        print(col("  No open ports found on scanned range.", C.GREY))
        return

    # Column header
    hdr = f"  {'PORT':<7}{'SERVICE':<18}{'RISK':<12}{'BANNER / NOTE'}"
    print(col(hdr, C.GREY))
    print(section_line())

    for p in open_ports:
        port_str    = col(f"{p['port']:<7}", C.CYAN)
        service_str = f"{p['service']:<18}"
        risk_int    = p["risk"]
        risk_str    = RISK_LABELS[risk_int]

        # Truncate banner / note for display
        detail = p["banner"] if p["banner"] else p["note"]
        if len(detail) > 38:
            detail = detail[:35] + "..."
        detail_str  = col(detail, RISK_COLORS.get(risk_int, C.WHITE))

        print(f"  {port_str}{service_str}{risk_str}  {detail_str}")

        # Show advisory for high+ risk ports
        if risk_int >= 3:
            advisory = f"     ⚠  {p['note']}"
            print(col(advisory, RISK_COLORS[risk_int]))

def print_summary(results: dict, elapsed: float):
    """Print a final summary table."""
    print()
    print(banner_line("═"))
    print(col("  SCAN SUMMARY", C.BOLD, C.CYAN))
    print(banner_line("═"))

    total_open = sum(len(v) for v in results.values())
    critical   = sum(1 for v in results.values()
                     for p in v if p["risk"] == 4)
    high       = sum(1 for v in results.values()
                     for p in v if p["risk"] == 3)

    print(col(f"\n  Hosts scanned    : {len(results)}", C.WHITE))
    print(col(f"  Open ports found : {total_open}", C.WHITE))

    if critical:
        print(col(f"  CRITICAL issues  : {critical}", C.RED, C.BOLD))
    if high:
        print(col(f"  HIGH risk ports  : {high}", C.ORANGE, C.BOLD))
    if not critical and not high:
        print(col("  No critical/high-risk ports found.", C.GREEN))

    print(col(f"\n  Elapsed time     : {elapsed:.1f}s", C.GREY))
    print()
    print(banner_line("═"))

    # Top findings across all hosts
    findings = []
    for ip, ports in results.items():
        for p in ports:
            if p["risk"] >= 3:
                findings.append((ip, p))

    if findings:
        print(col("\n  TOP FINDINGS TO REMEDIATE", C.BOLD, C.RED))
        print(section_line())
        for ip, p in sorted(findings, key=lambda x: -x[1]["risk"])[:15]:
            badge = RISK_LABELS[p["risk"]]
            print(f"  {badge}  {col(ip,'',C.CYAN)}:{col(str(p['port']),'',C.WHITE)}"
                  f"  {p['service']:<16}  {p['note'][:42]}")
    print()

# ──────────────────────────────────────────────
# MAIN ORCHESTRATION
# ──────────────────────────────────────────────

def parse_args():
    parser = argparse.ArgumentParser(
        description="Network Vulnerability Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "--target", "-t",
        help="Target CIDR range or single IP (default: auto-detect local /24)",
    )
    parser.add_argument(
        "--ports", "-p",
        help="Comma-separated port list (default: built-in common port list)",
    )
    parser.add_argument(
        "--threads", "-T",
        type=int, default=100,
        help="Max concurrent threads for host discovery (default: 100)",
    )
    parser.add_argument(
        "--port-threads",
        type=int, default=60,
        help="Max concurrent threads per host port scan (default: 60)",
    )
    parser.add_argument(
        "--timeout", "-w",
        type=float, default=0.5,
        help="Socket timeout in seconds (default: 0.5)",
    )
    parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable ANSI colour output",
    )
    parser.add_argument(
        "--skip-discovery",
        action="store_true",
        help="Skip host discovery – scan target directly",
    )
    return parser.parse_args()


def main():
    args = parse_args()

    global USE_COLOR
    if args.no_color:
        USE_COLOR = False
        C.disable()

    # ── Parse port list ───────────────────────
    if args.ports:
        try:
            ports = [int(p.strip()) for p in args.ports.split(",")]
        except ValueError:
            print("ERROR: --ports must be a comma-separated list of integers.")
            sys.exit(1)
    else:
        ports = DEFAULT_PORTS

    # ── Determine target network ──────────────
    local_ip = get_local_ip()

    if args.target:
        raw = args.target
        # Single IP passed: scan just that host
        if "/" not in raw:
            network = raw + "/32"
        else:
            network = raw
        try:
            ipaddress.IPv4Network(network, strict=False)
        except ValueError:
            print(f"ERROR: Invalid target '{args.target}'")
            sys.exit(1)
    else:
        network = get_network_range(local_ip)

    print_header()
    print_network_info(local_ip, network)

    net_obj  = ipaddress.IPv4Network(network, strict=False)
    is_single = net_obj.num_addresses <= 2    # /32 or /31

    # ── Host Discovery ────────────────────────
    if args.skip_discovery or is_single:
        live_hosts = [str(h) for h in net_obj.hosts()] or [args.target]
        print(col(f"  Skipping discovery – targeting {len(live_hosts)} host(s) directly.\n",
                  C.GREY))
    else:
        host_count = net_obj.num_addresses - 2
        print(col(f"  [1/2]  DISCOVERING HOSTS on {network}  "
                  f"({host_count} addresses)...\n", C.BOLD))

        discovered_bar = {"last": 0}
        def on_progress(done, total):
            # Throttle redraws
            if done - discovered_bar["last"] >= 5 or done == total:
                discovered_bar["last"] = done
                progress_bar(done, total, label="  Ping sweep")

        t0 = time.time()
        live_hosts = discover_hosts(
            network,
            timeout=args.timeout,
            max_workers=args.threads,
            progress_cb=on_progress,
        )
        elapsed_discovery = time.time() - t0
        sys.stdout.write("\r" + " " * 70 + "\r")   # clear progress line

        if not live_hosts:
            print(col("\n  No live hosts found.  "
                      "Try --skip-discovery or a wider timeout.\n", C.ORANGE))
            sys.exit(0)

        print(col(f"\n  Found {len(live_hosts)} live host(s) "
                  f"in {elapsed_discovery:.1f}s\n", C.GREEN))

    # ── Port Scanning ─────────────────────────
    print(col(f"  [2/2]  PORT SCANNING  ({len(ports)} ports × {len(live_hosts)} host(s))\n",
              C.BOLD))

    all_results = {}
    scan_start  = time.time()

    for idx, ip in enumerate(live_hosts, 1):
        prefix = col(f"  [{idx}/{len(live_hosts)}]", C.GREY)
        sys.stdout.write(f"\r{prefix}  Scanning {col(ip,'',C.CYAN)}...{' '*20}")
        sys.stdout.flush()

        hostname   = get_hostname(ip)
        open_ports = scan_host_ports(
            ip, ports,
            timeout=args.timeout,
            max_workers=args.port_threads,
        )
        all_results[ip] = open_ports
        print_host_result(ip, hostname, open_ports)

    elapsed_total = time.time() - scan_start
    print_summary(all_results, elapsed_total)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(col("\n\n  Scan interrupted by user.\n", C.YELLOW))
        sys.exit(0)
