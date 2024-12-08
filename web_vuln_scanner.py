#!/usr/bin/env python3

import argparse
import requests
import socket
import ssl
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urljoin
import sys
from datetime import datetime

class WebVulnScanner:
    def __init__(self, target_url, threads=5):
        self.target_url = target_url if target_url.startswith(('http://', 'https://')) else f'http://{target_url}'
        self.threads = threads
        self.common_dirs = [
            'admin/', 'login/', 'wp-admin/', 'backup/', 'wp-content/',
            'uploads/', 'images/', 'includes/', 'tmp/', 'old/', 'backup/',
            'css/', 'js/', 'test/', 'demo/', 'database/', 'backup.sql',
            '.git/', '.env', 'config.php', 'phpinfo.php'
        ]
        self.open_ports = []

    def scan_directory(self, directory):
        try:
            url = urljoin(self.target_url, directory)
            response = requests.get(url, timeout=5, allow_redirects=False)
            if response.status_code in [200, 301, 302, 403]:
                return f"[+] Found directory: {url} (Status: {response.status_code})"
        except:
            pass
        return None

    def directory_enumeration(self):
        print("\n[*] Starting Directory Enumeration...")
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            results = executor.map(self.scan_directory, self.common_dirs)
            for result in results:
                if result:
                    print(result)

    def check_headers(self):
        print("\n[*] Checking HTTP Headers...")
        try:
            response = requests.get(self.target_url)
            headers = response.headers
            
            security_headers = {
                'X-XSS-Protection': 'Missing XSS Protection Header',
                'X-Frame-Options': 'Missing Clickjacking Protection Header',
                'X-Content-Type-Options': 'Missing MIME Sniffing Protection Header',
                'Strict-Transport-Security': 'Missing HSTS Header',
                'Content-Security-Policy': 'Missing Content Security Policy Header'
            }

            for header, message in security_headers.items():
                if header not in headers:
                    print(f"[-] {message}")
                else:
                    print(f"[+] {header}: {headers[header]}")
                    
            print(f"[+] Server: {headers.get('Server', 'Not disclosed')}")
        except Exception as e:
            print(f"[-] Error checking headers: {str(e)}")

    def port_scan(self, port):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        target = self.target_url.split('://')[1].split('/')[0]
        result = sock.connect_ex((target, port))
        if result == 0:
            service = socket.getservbyport(port, 'tcp')
            self.open_ports.append(f"[+] Port {port} ({service}): Open")
        sock.close()

    def scan_ports(self):
        print("\n[*] Starting Port Scan...")
        common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995, 3306, 8080, 8443]
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            executor.map(self.port_scan, common_ports)
        
        for result in sorted(self.open_ports):
            print(result)

    def check_ssl(self):
        print("\n[*] Checking SSL/TLS Configuration...")
        if not self.target_url.startswith('https'):
            print("[-] Site is not using HTTPS")
            return

        try:
            hostname = self.target_url.split('://')[1].split('/')[0]
            context = ssl.create_default_context()
            with socket.create_connection((hostname, 443)) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    
                    # Check certificate expiration
                    not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                    if not_after < datetime.now():
                        print("[-] SSL Certificate has expired!")
                    else:
                        print("[+] SSL Certificate is valid")
                    
                    # Print certificate information
                    print(f"[+] Certificate expires: {cert['notAfter']}")
                    print(f"[+] Issued to: {cert['subject'][-1][1]}")
                    print(f"[+] Issued by: {cert['issuer'][-1][1]}")
        except Exception as e:
            print(f"[-] SSL/TLS Error: {str(e)}")

    def run_scan(self):
        print(f"\n[+] Starting vulnerability scan on {self.target_url}")
        print("=" * 60)
        
        self.directory_enumeration()
        self.check_headers()
        self.scan_ports()
        self.check_ssl()
        
        print("\n[+] Scan completed!")

def main():
    parser = argparse.ArgumentParser(description='Web Vulnerability Scanner')
    parser.add_argument('-u', '--url', required=True, help='Target URL to scan')
    parser.add_argument('-t', '--threads', type=int, default=5, help='Number of threads (default: 5)')
    args = parser.parse_args()

    scanner = WebVulnScanner(args.url, args.threads)
    scanner.run_scan()

if __name__ == '__main__':
    main()
