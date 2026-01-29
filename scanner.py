import socket
import threading
import sys
import nmap
from concurrent.futures import ThreadPoolExecutor
import argparse
import re
from datetime import datetime

class EthicalPortScanner:
    def __init__(self, target):
        self.target = socket.gethostbyname(target)
        self.open_ports = []
        self.services = {}
        self.vulnerabilities = {}
        print(f"[+] Scanning target: {self.target}")

    def scan_port(self, port):
        """Scan individual port using socket"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((self.target, port))
            if result == 0:
                self.open_ports.append(port)
                service = self.grab_banner(port)
                self.services[port] = service
                vulns = self.check_vulnerabilities(port, service)
                if vulns:
                    self.vulnerabilities[port] = vulns
                print(f"[+] Port {port}: Open - {service}")
            sock.close()
        except:
            pass

    def grab_banner(self, port):
        """Grab service banner for identification"""
        try:
            sock = socket.socket()
            sock.settimeout(2)
            sock.connect((self.target, port))
            sock.send(b'\r\n')
            banner = sock.recv(1024).decode().strip()
            sock.close()
            return banner[:100] or f"Port {port} open"
        except:
            return f"Port {port} open (no banner)"

    def check_vulnerabilities(self, port, service):
        """Basic vulnerability detection patterns"""
        vulns = []
        service_lower = service.lower()
        
        # Common vulnerable services patterns
        vuln_patterns = {
            'ssh': ['OpenSSH_4.', 'OpenSSH_5.'],
            23: ['telnet'],  # Telnet always vulnerable
            21: ['vsftpd', 'ProFTPD'],  # FTP services
            445: ['Microsoft-DS', 'SMB'],  # SMB vulnerabilities
            139: ['netbios-ssn']  # NetBIOS
        }
        
        if port in vuln_patterns:
            for pattern in vuln_patterns[port]:
                if pattern in service_lower:
                    vulns.append(f"Potential {pattern} vulnerability")
        
        # Specific checks
        if 'ssh' in service_lower and any(old_version in service_lower for old_version in vuln_patterns['ssh']):
            vulns.append("Outdated SSH version detected")
            
        return vulns if vulns else None

    def nmap_scan(self):
        """Advanced scan using nmap"""
        try:
            nm = nmap.PortScanner()
            print("[*] Running Nmap scan...")
            nm.scan(self.target, '1-1000', arguments='-sV -sC')
            
            for host in nm.all_hosts():
                print(f"[*] Nmap results for {host}:")
                for proto in nm[host].all_protocols():
                    ports = nm[host][proto].keys()
                    for port in ports:
                        state = nm[host][proto][port]['state']
                        service = nm[host][proto][port].get('name', 'unknown')
                        version = nm[host][proto][port].get('version', '')
                        print(f"    {port}/{proto}: {state} {service} {version}")
        except Exception as e:
            print(f"[-] Nmap scan failed: {e}")

    def full_scan(self, threads=100, ports=range(1, 1001)):
        """Execute full multi-threaded scan"""
        print(f"[*] Starting scan with {threads} threads...")
        start_time = datetime.now()
        
        with ThreadPoolExecutor(max_workers=threads) as executor:
            executor.map(self.scan_port, ports)
        
        end_time = datetime.now()
        print(f"\n[+] Scan completed in {(end_time - start_time).total_seconds():.2f}s")

    def generate_report(self):
        """Generate professional report"""
        print("\n" + "="*60)
        print("          SCAN REPORT")
        print("="*60)
        print(f"Target: {self.target}")
        print(f"Open ports found: {len(self.open_ports)}")
        print(f"Vulnerable services: {len([v for v in self.vulnerabilities.values()])}")
        
        print("\nOpen Ports:")
        for port in sorted(self.open_ports):
            service = self.services.get(port, 'Unknown')
            vulns = self.vulnerabilities.get(port)
            status = " [!] VULNERABLE" if vulns else ""
            print(f"  {port:5} | {service[:40]:40} | {status}")
            
            if vulns:
                for vuln in vulns:
                    print(f"      └── {vuln}")

def main():
    parser = argparse.ArgumentParser(description="Ethical Port Scanner & Vulnerability Detector")
    parser.add_argument("target", help="Target IP or hostname")
    parser.add_argument("-p", "--ports", default="1-1000", help="Port range (default: 1-1000)")
    parser.add_argument("-t", "--threads", type=int, default=100, help="Number of threads (default: 100)")
    parser.add_argument("--nmap", action="store_true", help="Run additional Nmap scan")
    
    args = parser.parse_args()
    
    # Parse port range
    if '-' in args.ports:
        start, end = map(int, args.ports.split('-'))
        ports = range(start, end + 1)
    else:
        ports = range(1, 1001)
    
    scanner = EthicalPortScanner(args.target)
    scanner.full_scan(threads=args.threads, ports=ports)
    
    if args.nmap:
        scanner.nmap_scan()
    
    scanner.generate_report()

if __name__ == "__main__":
    print("Ethical Port Scanner v1.0")
    print("WARNING: Only use on systems you own or have permission to scan!")
    main()
