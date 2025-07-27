import os
import re
import socket
import subprocess
import ipaddress
from datetime import datetime
import concurrent.futures

def get_local_network_info():
    """Get local IP address and subnet mask using ipconfig"""
    result = subprocess.run(['ipconfig'], capture_output=True, text=True)
    ip_pattern = r"IPv4 Address[ .:]+(\d+\.\d+\.\d+\.\d+)"
    mask_pattern = r"Subnet Mask[ .:]+(\d+\.\d+\.\d+\.\d+)"
    
    ip_match = re.search(ip_pattern, result.stdout)
    mask_match = re.search(mask_pattern, result.stdout)
    
    if ip_match and mask_match:
        ip = ip_match.group(1)
        mask = mask_match.group(1)
        network = ipaddress.IPv4Network(f"{ip}/{mask}", strict=False)
        return str(network.network_address), str(network.netmask)
    return None, None

def ping_host(ip):
    """Ping a host to check if it's alive (Windows)"""
    try:
        res = subprocess.run(
            ['ping', '-n', '1', '-w', '500', ip],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        return res.returncode == 0
    except:
        return False

def scan_arp():
    """Scan local network using ARP"""
    print("[*] Scanning network using ARP...")
    result = subprocess.run(['arp', '-a'], capture_output=True, text=True)
    devices = []
    
    for line in result.stdout.split('\n'):
        if "dynamic" in line.lower():
            parts = line.split()
            if len(parts) >= 3:
                ip = parts[0]
                mac = parts[1]
                devices.append((ip, mac))
    return devices

def port_scan(ip, ports):
    """Scan for open ports on a target IP"""
    open_ports = []
    for port in ports:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(1)
                result = s.connect_ex((ip, port))
                if result == 0:
                    open_ports.append(port)
        except:
            continue
    return open_ports

def scan_ports(ip):
    """Scan common ports with service detection"""
    common_ports = {
        21: "FTP",
        22: "SSH",
        23: "Telnet",
        25: "SMTP",
        53: "DNS",
        80: "HTTP",
        110: "POP3",
        135: "MSRPC",
        139: "NetBIOS",
        143: "IMAP",
        443: "HTTPS",
        445: "SMB",
        1433: "MSSQL",
        3306: "MySQL",
        3389: "RDP",
        8080: "HTTP-Proxy"
    }
    
    print(f"[*] Scanning {ip} for open ports...")
    open_ports = port_scan(ip, list(common_ports.keys()))
    
    results = []
    for port in open_ports:
        service = common_ports.get(port, "Unknown")
        results.append((port, service))
    return results

def check_vulnerabilities(ip, port_service_pairs):
    """Check for common vulnerabilities based on open ports"""
    vulnerabilities = []
    
    for port, service in port_service_pairs:
        # Check for potentially risky services
        if port == 23:
            vulnerabilities.append(("Telnet Service", "High", 
                                   "Telnet transmits credentials in clear text"))
        
        elif port == 135 or port == 139 or port == 445:
            vulnerabilities.append((f"{service} Service", "High", 
                                   "Potential target for EternalBlue exploit"))
        
        elif port == 22:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(2)
                    s.connect((ip, port))
                    banner = s.recv(1024).decode(errors='ignore')
                    if "SSH-2.0-OpenSSH_7.4" in banner:
                        vulnerabilities.append(("OpenSSH 7.4", "Medium", 
                                              "Vulnerable to user enumeration (CVE-2018-15473)"))
            except:
                continue
        
        elif port == 80 or port == 8080 or port == 443:
            vulnerabilities.append((f"{service} Service", "Medium", 
                                   "Potential web vulnerabilities (check manually)"))
        
        elif port == 3389:
            vulnerabilities.append(("RDP Service", "Medium", 
                                   "Potential target for brute-force attacks"))
    
    return vulnerabilities

def generate_report(devices, scan_results):
    """Generate a security report"""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"network_scan_report_{timestamp}.txt"
    
    with open(filename, 'w') as f:
        f.write("Network Security Scan Report\n")
        f.write(f"Generated at: {datetime.now()}\n\n")
        f.write(f"Scanned Devices: {len(devices)}\n")
        f.write("=" * 50 + "\n\n")
        
        for device in devices:
            ip, mac = device
            f.write(f"Device: {ip} ({mac})\n")
            
            if ip in scan_results:
                ports = scan_results[ip].get('ports', [])
                vulns = scan_results[ip].get('vulnerabilities', [])
                
                if ports:
                    f.write("  Open Ports:\n")
                    for port, service in ports:
                        f.write(f"    - {port}/TCP ({service})\n")
                
                if vulns:
                    f.write("  Potential Vulnerabilities:\n")
                    for name, severity, description in vulns:
                        f.write(f"    - [{severity}] {name}: {description}\n")
                else:
                    f.write("  No critical vulnerabilities found\n")
            else:
                f.write("  Could not complete scan\n")
            
            f.write("\n" + "-" * 50 + "\n\n")
        
        f.write("Scan completed.\n")
    
    print(f"[+] Report saved as {filename}")
    return filename

def main():
    print("Network Vulnerability Scanner for Windows")
    print("=" * 50 + "\n")
    
    # Get network information
    network, netmask = get_local_network_info()
    if not network or not netmask:
        print("[-] Could not determine network information")
        return
    
    print(f"[*] Network: {network}")
    print(f"[*] Subnet Mask: {netmask}\n")
    
    # Discover devices
    devices = scan_arp()
    if not devices:
        print("[-] No devices found in ARP table")
        return
    
    print(f"[+] Found {len(devices)} devices in the local network")
    
    # Scan devices
    scan_results = {}
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        future_to_ip = {}
        for ip, mac in devices:
            future = executor.submit(scan_device, ip)
            future_to_ip[future] = ip
        
        for future in concurrent.futures.as_completed(future_to_ip):
            ip = future_to_ip[future]
            try:
                result = future.result()
                scan_results[ip] = result
            except Exception as e:
                print(f"[-] Error scanning {ip}: {str(e)}")
                scan_results[ip] = {'error': str(e)}
    
    # Generate report
    report_file = generate_report(devices, scan_results)
    print(f"\n[+] Scan completed. Results saved to {report_file}")
    
    # Security recommendations
    print("\nSecurity Recommendations:")
    print("- Change default credentials on network devices")
    print("- Disable Telnet and use SSH instead")
    print("- Ensure SMB ports (139,445) are not exposed to the internet")
    print("- Keep all systems updated with the latest security patches")
    print("- Use a firewall to restrict unnecessary ports")

def scan_device(ip):
    """Scan an individual device"""
    result = {'ip': ip, 'ports': [], 'vulnerabilities': []}
    
    # Skip scanning the local machine
    if ip == socket.gethostbyname(socket.gethostname()):
        result['ports'] = [("Local Machine", "Skipped")]
        return result
    
    # Check if host is responsive
    if not ping_host(ip):
        result['error'] = "Host not responsive"
        return result
    
    # Port scan
    open_ports = scan_ports(ip)
    result['ports'] = open_ports
    
    # Vulnerability check
    if open_ports:
        vulnerabilities = check_vulnerabilities(ip, open_ports)
        result['vulnerabilities'] = vulnerabilities
    
    return result

if __name__ == "__main__":
    main()


    