#!/usr/bin/env python3

import argparse
import requests
import socket
import ssl
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urljoin, urlparse
import sys
from datetime import datetime
import whois
import re
from difflib import SequenceMatcher
import tldextract
import dns.resolver

class WebVulnScanner:
    def __init__(self, target_url, threads=5):
        self.target_url = target_url if target_url.startswith(('http://', 'https://')) else f'http://{target_url}'
        self.threads = threads
        self.domain = urlparse(self.target_url).netloc
        self.common_dirs = [
            'admin/', 'login/', 'wp-admin/', 'backup/', 'wp-content/',
            'uploads/', 'images/', 'includes/', 'tmp/', 'old/', 'backup/',
            'css/', 'js/', 'test/', 'demo/', 'database/', 'backup.sql',
            '.git/', '.env', 'config.php', 'phpinfo.php'
        ]
        self.open_ports = []
        self.legitimate_domains = [
            'google.com', 'facebook.com', 'amazon.com', 'apple.com',
            'microsoft.com', 'paypal.com', 'netflix.com', 'instagram.com'
        ]

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
            return False

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
                        return False
                    else:
                        print("[+] SSL Certificate is valid")
                    
                    # Print certificate information
                    print(f"[+] Certificate expires: {cert['notAfter']}")
                    print(f"[+] Issued to: {cert['subject'][-1][1]}")
                    print(f"[+] Issued by: {cert['issuer'][-1][1]}")
                    return True
        except Exception as e:
            print(f"[-] SSL/TLS Error: {str(e)}")
            return False

    def check_domain_age(self):
        print("\n[*] Checking Domain Age...")
        try:
            w = whois.whois(self.domain)
            creation_date = w.creation_date
            if isinstance(creation_date, list):
                creation_date = creation_date[0]
            
            domain_age = (datetime.now() - creation_date).days
            print(f"[+] Domain age: {domain_age} days")
            
            if domain_age < 30:
                print("[-] Warning: Domain is less than 30 days old!")
                return False
            return True
        except Exception as e:
            print(f"[-] Error checking domain age: {str(e)}")
            return False

    def check_domain_similarity(self):
        print("\n[*] Checking Domain Similarity...")
        extracted = tldextract.extract(self.domain)
        domain_name = extracted.domain
        
        similar_domains = []
        for legitimate in self.legitimate_domains:
            legit_extracted = tldextract.extract(legitimate)
            legit_domain = legit_extracted.domain
            similarity = SequenceMatcher(None, domain_name, legit_domain).ratio()
            
            if similarity > 0.75:  # 75% similarity threshold
                similar_domains.append((legitimate, similarity * 100))
        
        if similar_domains:
            print("[-] Warning: Similar to legitimate domains:")
            for domain, similarity in similar_domains:
                print(f"    - {domain} (Similarity: {similarity:.2f}%)")
            return False
        return True

    def check_suspicious_patterns(self):
        print("\n[*] Checking Suspicious URL Patterns...")
        suspicious_patterns = [
            r'secure.*login',
            r'account.*verify',
            r'banking.*secure',
            r'signin.*verify',
            r'security.*check',
            r'update.*account',
            r'verify.*identity'
        ]
        
        url_string = self.target_url.lower()
        found_patterns = []
        
        for pattern in suspicious_patterns:
            if re.search(pattern, url_string):
                found_patterns.append(pattern)
        
        if found_patterns:
            print("[-] Warning: Suspicious patterns found in URL:")
            for pattern in found_patterns:
                print(f"    - Matches pattern: {pattern}")
            return False
        return True

    def analyze_dns_records(self):
        print("\n[*] Analyzing DNS Records...")
        try:
            domain = urlparse(self.target_url).netloc
            records_exist = False
            
            # Check MX Records
            try:
                mx_records = dns.resolver.resolve(domain, 'MX')
                print("[+] MX Records found:")
                for mx in mx_records:
                    print(f"    - {mx.exchange}")
                records_exist = True
            except:
                print("[-] No MX records found")
            
            # Check A Records
            try:
                a_records = dns.resolver.resolve(domain, 'A')
                print("[+] A Records found:")
                for a in a_records:
                    print(f"    - {a.address}")
                records_exist = True
            except:
                print("[-] No A records found")
            
            return records_exist
        except Exception as e:
            print(f"[-] Error analyzing DNS records: {str(e)}")
            return False

    def check_for_phishing(self):
        print("\n[*] Starting Phishing Detection...")
        print("=" * 60)
        
        checks = {
            "SSL Certificate": self.check_ssl(),
            "Domain Age": self.check_domain_age(),
            "Domain Similarity": self.check_domain_similarity(),
            "Suspicious Patterns": self.check_suspicious_patterns(),
            "DNS Records": self.analyze_dns_records()
        }
        
        failed_checks = [check for check, result in checks.items() if not result]
        
        print("\n[*] Phishing Detection Summary:")
        if failed_checks:
            print("[-] Warning: Potential phishing site detected!")
            print("[-] Failed checks:")
            for check in failed_checks:
                print(f"    - {check}")
        else:
            print("[+] No obvious phishing indicators detected")
        
        return len(failed_checks) == 0

    def run_scan(self):
        print(f"\n[+] Starting vulnerability scan on {self.target_url}")
        print("=" * 60)
        
        self.directory_enumeration()
        self.check_headers()
        self.scan_ports()
        self.check_for_phishing()
        
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
