#!/usr/bin/env python3
"""
CyberSleuth Pro - Advanced Multi-Threaded OSINT & Vulnerability Scanner
"""

import os
import sys
import json
import time
import argparse
import requests
import socket
import dns.resolver
from bs4 import BeautifulSoup
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from multiprocessing import cpu_count
import whois
import shodan
import builtwith
import warnings
import re
import dns.reversename
import ipaddress

# Suppress warnings
warnings.filterwarnings('ignore')

# Configuration
API_KEYS = {
    'shodan': 'YOUR_SHODAN_API_KEY',
    'virustotal': 'YOUR_VIRUSTOTAL_API_KEY'
}
USER_AGENT = "CyberSleuthPro/2.0 (+https://github.com/sudesh3107/CyberSleuth)"
THREADS = cpu_count() * 2  # Utilize all CPU cores aggressively
TIMEOUT = 10

class CyberSleuth:
    def __init__(self, target):
        self.target = target
        self.target_ip = None
        self.results = {
            'target': target,
            'ip_address': None,
            'domain_info': {},
            'subdomains': [],
            'dns_records': {},
            'ports': [],
            'technologies': [],
            'emails': [],
            'phone_numbers': [],
            'social_media': [],
            'files': [],
            'vulnerabilities': [],
            'shodan_data': {},
            'scan_time': None
        }
        self.resolve_target()
    
    def resolve_target(self):
        """Resolve domain to IP or validate IP address"""
        try:
            # Check if input is already an IP address
            if self.is_valid_ip(self.target):
                self.target_ip = self.target
                self.results['ip_address'] = self.target
            else:
                # Resolve domain to IP
                self.target_ip = socket.gethostbyname(self.target)
                self.results['ip_address'] = self.target_ip
        except socket.gaierror:
            print(f"[!] Error: Could not resolve {self.target}")
            sys.exit(1)
    
    def is_valid_ip(self, address):
        """Check if the input is a valid IP address"""
        try:
            ipaddress.ip_address(address)
            return True
        except ValueError:
            return False
    
    def run_full_scan(self):
        """Execute all scan modules with maximum parallelism"""
        start_time = time.time()
        
        with ThreadPoolExecutor(max_workers=THREADS) as executor:
            futures = {
                executor.submit(self.get_domain_info): 'domain_info',
                executor.submit(self.find_subdomains): 'subdomains',
                executor.submit(self.dns_enumeration): 'dns_records',
                executor.submit(self.port_scan): 'ports',
                executor.submit(self.tech_stack_analysis): 'technologies',
                executor.submit(self.email_harvesting): 'emails',
                executor.submit(self.phone_number_harvesting): 'phone_numbers',
                executor.submit(self.file_discovery): 'files',
                executor.submit(self.shodan_intel): 'shodan_data'
            }
            
            for future in as_completed(futures):
                key = futures[future]
                try:
                    result = future.result()
                    self.results[key] = result
                except Exception as e:
                    print(f"[!] Error in {key}: {str(e)}")
        
        self.vulnerability_scan()
        self.results['scan_time'] = time.time() - start_time
        return self.results
    
    def get_domain_info(self):
        """Retrieve comprehensive domain registration information"""
        try:
            # Only run whois if target is a domain, not IP
            if not self.is_valid_ip(self.target):
                domain = whois.whois(self.target)
                return {
                    'registrar': domain.registrar,
                    'creation_date': str(domain.creation_date),
                    'expiration_date': str(domain.expiration_date),
                    'name_servers': domain.name_servers,
                    'status': domain.status,
                    'emails': domain.emails
                }
            return {'info': 'IP address - no domain info available'}
        except Exception as e:
            return {'error': str(e)}
    
    def find_subdomains(self):
        """Brute-force subdomains using multiple techniques"""
        # Only run for domains, not IPs
        if self.is_valid_ip(self.target):
            return []
            
        subdomains = set()
        # More comprehensive wordlist
        wordlist = ["www", "mail", "ftp", "admin", "test", "dev", "staging",
                    "api", "app", "cdn", "cloud", "db", "demo", "git", "m",
                    "mobile", "new", "old", "secure", "shop", "beta", "vpn",
                    "web", "ns1", "ns2", "smtp", "pop", "imap", "static"]
        wordlist += [f"sd{i}" for i in range(100)]  # Generate 100 subdomains
        
        # DNS Brute-force
        with ThreadPoolExecutor(max_workers=THREADS) as executor:
            futures = [executor.submit(self.check_subdomain, f"{sub}.{self.target}") 
                      for sub in wordlist]
            
            for future in as_completed(futures):
                if future.result():
                    subdomains.add(future.result())
        
        return list(subdomains)
    
    def check_subdomain(self, subdomain):
        """Verify if subdomain exists"""
        try:
            socket.gethostbyname(subdomain)
            return subdomain
        except:
            return None
    
    def dns_enumeration(self):
        """Retrieve all DNS records for the domain"""
        # Only run for domains, not IPs
        if self.is_valid_ip(self.target):
            return {}
            
        record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA', 'CNAME', 'SRV']
        records = {}
        
        for rtype in record_types:
            try:
                answers = dns.resolver.resolve(self.target, rtype)
                records[rtype] = [str(r) for r in answers]
            except:
                pass
        
        # Reverse DNS lookup for IP ranges
        try:
            rev_name = dns.reversename.from_address(self.target_ip)
            ptr = str(dns.resolver.resolve(rev_name, "PTR")[0])
            records['PTR'] = ptr
        except:
            pass
        
        return records
    
    def port_scan(self):
        """Scan common ports with multi-threading"""
        ports = [
            21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 
            445, 993, 995, 1723, 3306, 3389, 5900, 8080, 8443,
            27017, 11211, 2049, 5060, 5061, 1433, 5432, 1521
        ]
        
        open_ports = []
        
        with ThreadPoolExecutor(max_workers=THREADS) as executor:
            futures = [executor.submit(self.check_port, port) for port in ports]
            
            for future in as_completed(futures):
                if future.result():
                    open_ports.append({
                        'port': future.result(),
                        'service': self.port_to_service(future.result())
                    })
        
        return open_ports
    
    def port_to_service(self, port):
        """Map port number to common service name"""
        port_map = {
            21: 'FTP',
            22: 'SSH',
            23: 'Telnet',
            25: 'SMTP',
            53: 'DNS',
            80: 'HTTP',
            110: 'POP3',
            111: 'RPC',
            135: 'MSRPC',
            139: 'NetBIOS',
            143: 'IMAP',
            443: 'HTTPS',
            445: 'SMB',
            993: 'IMAPS',
            995: 'POP3S',
            1723: 'PPTP',
            3306: 'MySQL',
            3389: 'RDP',
            5900: 'VNC',
            8080: 'HTTP-Alt',
            8443: 'HTTPS-Alt',
            27017: 'MongoDB',
            11211: 'Memcached',
            2049: 'NFS',
            5060: 'SIP',
            5061: 'SIPS',
            1433: 'MSSQL',
            5432: 'PostgreSQL',
            1521: 'Oracle'
        }
        return port_map.get(port, 'Unknown')
    
    def check_port(self, port):
        """Check if a port is open using the resolved IP"""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)  # Faster timeout for port scanning
        result = sock.connect_ex((self.target_ip, port))
        sock.close()
        return port if result == 0 else None
    
    def tech_stack_analysis(self):
        """Identify web technologies in use"""
        try:
            # Try both HTTP and HTTPS
            for scheme in ['http', 'https']:
                try:
                    tech = builtwith.parse(f"{scheme}://{self.target}")
                    if tech:
                        return tech
                except:
                    continue
            return {}
        except:
            return {}
    
    def email_harvesting(self):
        """Scrape emails from target website"""
        emails = set()
        try:
            for scheme in ['http', 'https']:
                try:
                    response = requests.get(
                        f"{scheme}://{self.target}",
                        headers={'User-Agent': USER_AGENT},
                        timeout=TIMEOUT,
                        verify=False
                    )
                    found_emails = re.findall(
                        r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', 
                        response.text
                    )
                    emails.update(found_emails)
                    
                    # Parse all links and search in linked pages
                    soup = BeautifulSoup(response.text, 'html.parser')
                    links = [a.get('href') for a in soup.find_all('a', href=True)]
                    
                    # Check up to 5 internal links
                    internal_links = [
                        link for link in links 
                        if link.startswith('/') or self.target in link
                    ][:5]
                    
                    for link in internal_links:
                        if link.startswith('/'):
                            full_link = f"{scheme}://{self.target}{link}"
                        else:
                            full_link = link
                            
                        try:
                            link_response = requests.get(
                                full_link,
                                headers={'User-Agent': USER_AGENT},
                                timeout=TIMEOUT,
                                verify=False
                            )
                            found_emails = re.findall(
                                r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', 
                                link_response.text
                            )
                            emails.update(found_emails)
                        except:
                            continue
                except:
                    continue
            return list(emails)
        except:
            return []
    
    def phone_number_harvesting(self):
        """Scrape phone numbers from target website"""
        phone_numbers = set()
        try:
            for scheme in ['http', 'https']:
                try:
                    response = requests.get(
                        f"{scheme}://{self.target}",
                        headers={'User-Agent': USER_AGENT},
                        timeout=TIMEOUT,
                        verify=False
                    )
                    # International phone number regex
                    found_numbers = re.findall(
                        r'(\+\d{1,3}[-.\s]?\(?\d{1,4}\)?[-.\s]?\d{1,4}[-.\s]?\d{1,4}[-.\s]?\d{1,4})', 
                        response.text
                    )
                    phone_numbers.update(found_numbers)
                except:
                    continue
            return list(phone_numbers)
        except:
            return []
    
    def file_discovery(self):
        """Discover interesting files on web server"""
        files = [
            '.env', '.git/config', 'robots.txt', 'sitemap.xml', 
            'backup.zip', 'credentials.txt', 'wp-config.php',
            'config.php', 'database.yml', 'settings.ini',
            'crossdomain.xml', 'phpinfo.php', 'test.php',
            'LICENSE', 'README.md', '.htaccess', '.DS_Store'
        ]
        
        found_files = []
        
        with ThreadPoolExecutor(max_workers=THREADS) as executor:
            futures = []
            for scheme in ['http', 'https']:
                for file in files:
                    futures.append(executor.submit(
                        self.check_file, 
                        f"{scheme}://{self.target}/{file}"
                    ))
            
            for future in as_completed(futures):
                if future.result():
                    found_files.append(future.result())
        
        return found_files
    
    def check_file(self, url):
        """Check if a file exists with HEAD request"""
        try:
            response = requests.head(
                url,
                headers={'User-Agent': USER_AGENT},
                timeout=TIMEOUT,
                allow_redirects=True,
                verify=False
            )
            return url if response.status_code == 200 else None
        except:
            return None
    
    def shodan_intel(self):
        """Retrieve Shodan intelligence data"""
        try:
            if not API_KEYS['shodan'] or API_KEYS['shodan'] == 'YOUR_SHODAN_API_KEY':
                return {'error': 'Shodan API key not configured'}
                
            api = shodan.Shodan(API_KEYS['shodan'])
            results = api.host(self.target_ip)
            return {
                'ip': results['ip_str'],
                'ports': results['ports'],
                'vulns': results.get('vulns', []),
                'hostnames': results['hostnames'],
                'org': results.get('org', ''),
                'asn': results.get('asn', ''),
                'last_update': results.get('last_update', ''),
                'services': self.extract_shodan_services(results)
            }
        except shodan.APIError as e:
            return {'error': str(e)}
        except:
            return {}
    
    def extract_shodan_services(self, shodan_data):
        """Extract service information from Shodan data"""
        services = []
        for item in shodan_data.get('data', []):
            service = {
                'port': item['port'],
                'transport': item['transport'],
                'product': item.get('product', ''),
                'version': item.get('version', ''),
                'banner': item.get('data', '')[:100] + '...' if 'data' in item else ''
            }
            services.append(service)
        return services
    
    def vulnerability_scan(self):
        """Perform actual vulnerability checks"""
        vulnerabilities = []
        
        # 1. Check for .git directory exposure
        if self.check_file(f"http://{self.target}/.git/HEAD"):
            vulnerabilities.append({
                "name": "Exposed .git Directory",
                "severity": "High",
                "description": "The .git directory is publicly accessible, potentially exposing source code and sensitive information",
                "solution": "Add 'deny from all' to .htaccess or remove the directory from production servers"
            })
        
        # 2. Check for directory listing
        dir_listing = self.check_directory_listing()
        if dir_listing:
            vulnerabilities.append({
                "name": "Directory Listing Enabled",
                "severity": "Medium",
                "description": f"Directory listing is enabled at: {dir_listing}",
                "solution": "Disable directory listing in web server configuration"
            })
        
        # 3. Check for common admin panels
        admin_panels = self.find_admin_panels()
        if admin_panels:
            vulnerabilities.append({
                "name": "Exposed Admin Interface",
                "severity": "Medium",
                "description": f"Admin panels found at: {', '.join(admin_panels)}",
                "solution": "Restrict access to admin interfaces via IP whitelisting or authentication"
            })
        
        # 4. Check for outdated server software
        server_header = self.get_server_header()
        if server_header and self.is_outdated_server(server_header):
            vulnerabilities.append({
                "name": "Outdated Server Software",
                "severity": "High",
                "description": f"Outdated server version detected: {server_header}",
                "solution": "Upgrade to the latest secure version of the web server software"
            })
        
        # 5. Check for common misconfigurations
        if self.check_file(f"http://{self.target}/.env"):
            vulnerabilities.append({
                "name": "Exposed Environment File",
                "severity": "Critical",
                "description": ".env file found containing potentially sensitive environment variables",
                "solution": "Move environment variables to secure storage and remove .env from web root"
            })
        
        # 6. Check for CORS misconfiguration
        if self.check_cors_misconfig():
            vulnerabilities.append({
                "name": "Insecure CORS Configuration",
                "severity": "Medium",
                "description": "Access-Control-Allow-Origin header set to '*' allowing cross-origin requests from any domain",
                "solution": "Configure proper CORS policies to restrict allowed origins"
            })
        
        # 7. Check for Clickjacking vulnerability
        if not self.check_clickjacking_protection():
            vulnerabilities.append({
                "name": "Clickjacking Vulnerability",
                "severity": "Medium",
                "description": "Missing X-Frame-Options header, making site vulnerable to UI redressing attacks",
                "solution": "Add 'X-Frame-Options: DENY' or 'SAMEORIGIN' to HTTP headers"
            })
        
        # 8. Check for insecure cookies
        if self.check_insecure_cookies():
            vulnerabilities.append({
                "name": "Insecure Cookies",
                "severity": "Medium",
                "description": "Cookies set without Secure or HttpOnly flags",
                "solution": "Set Secure and HttpOnly flags on all cookies"
            })
        
        self.results['vulnerabilities'] = vulnerabilities
    
    def check_directory_listing(self):
        """Check if directory listing is enabled"""
        test_dirs = ["images", "assets", "uploads", "static", "files", "media"]
        for directory in test_dirs:
            for scheme in ['http', 'https']:
                url = f"{scheme}://{self.target}/{directory}/"
                try:
                    response = requests.get(
                        url,
                        headers={'User-Agent': USER_AGENT},
                        timeout=TIMEOUT,
                        verify=False
                    )
                    # Check for common directory listing indicators
                    if "Index of /" in response.text or "<title>Directory listing for /" in response.text:
                        return url
                except:
                    continue
        return None
    
    def find_admin_panels(self):
        """Discover common admin panels"""
        admin_paths = [
            "admin", "wp-admin", "administrator", "backend", 
            "manager", "cms", "login", "controlpanel",
            "dashboard", "admin.php", "admin/login", "admincp",
            "user/login", "wp-login.php", "console", "system"
        ]
        found_panels = []
        
        with ThreadPoolExecutor(max_workers=THREADS) as executor:
            futures = []
            for path in admin_paths:
                for scheme in ['http', 'https']:
                    futures.append(executor.submit(
                        self.check_admin_panel, 
                        f"{scheme}://{self.target}/{path}"
                    ))
            
            for future in as_completed(futures):
                result = future.result()
                if result:
                    found_panels.append(result)
        
        return found_panels
    
    def check_admin_panel(self, url):
        """Check if admin panel exists"""
        try:
            response = requests.head(
                url,
                headers={'User-Agent': USER_AGENT},
                timeout=TIMEOUT,
                verify=False
            )
            if response.status_code == 200:
                return url
        except:
            return None
        return None
    
    def get_server_header(self):
        """Retrieve server header from response"""
        for scheme in ['http', 'https']:
            try:
                response = requests.head(
                    f"{scheme}://{self.target}",
                    headers={'User-Agent': USER_AGENT},
                    timeout=TIMEOUT,
                    verify=False
                )
                server_header = response.headers.get('Server', '')
                if server_header:
                    return server_header
            except:
                continue
        return None
    
    def is_outdated_server(self, server_header):
        """Check if server version is outdated"""
        # Check for known vulnerable versions
        outdated_versions = [
            "Apache/2.2", "Apache/2.4.0", "Apache/2.4.1", "Apache/2.4.2",
            "nginx/1.4", "nginx/1.6", "nginx/1.8", "nginx/1.10",
            "Microsoft-IIS/7.0", "Microsoft-IIS/7.5", "Microsoft-IIS/8.0",
            "OpenSSL/1.0.1", "OpenSSL/1.0.2", "PHP/5.6", "PHP/7.0"
        ]
        
        return any(version in server_header for version in outdated_versions)
    
    def check_cors_misconfig(self):
        """Check for insecure CORS configuration"""
        try:
            response = requests.get(
                f"http://{self.target}",
                headers={'User-Agent': USER_AGENT, 'Origin': 'https://attacker.com'},
                timeout=TIMEOUT,
                verify=False
            )
            cors_header = response.headers.get('Access-Control-Allow-Origin', '')
            return cors_header == '*' or cors_header == 'https://attacker.com'
        except:
            return False
    
    def check_clickjacking_protection(self):
        """Check for clickjacking protection headers"""
        for scheme in ['http', 'https']:
            try:
                response = requests.head(
                    f"{scheme}://{self.target}",
                    headers={'User-Agent': USER_AGENT},
                    timeout=TIMEOUT,
                    verify=False
                )
                frame_options = response.headers.get('X-Frame-Options', '').lower()
                content_security = response.headers.get('Content-Security-Policy', '').lower()
                
                if "deny" in frame_options or "sameorigin" in frame_options or "frame-ancestors" in content_security:
                    return True
            except:
                continue
        return False
    
    def check_insecure_cookies(self):
        """Check for insecure cookie settings"""
        for scheme in ['http', 'https']:
            try:
                response = requests.get(
                    f"{scheme}://{self.target}",
                    headers={'User-Agent': USER_AGENT},
                    timeout=TIMEOUT,
                    verify=False
                )
                cookies = response.headers.get('Set-Cookie', '')
                if cookies:
                    if 'Secure' not in cookies or 'HttpOnly' not in cookies:
                        return True
            except:
                continue
        return False

def main():
    parser = argparse.ArgumentParser(description="CyberSleuth Pro - Advanced OSINT & Vulnerability Scanner")
    parser.add_argument("target", help="Domain or IP address to scan")
    parser.add_argument("-o", "--output", help="Output file (JSON format)")
    parser.add_argument("-f", "--full", action="store_true", 
                        help="Perform full intensive scan (CPU heavy)")
    parser.add_argument("-v", "--verbose", action="store_true", 
                        help="Show detailed scan progress")
    args = parser.parse_args()
    
    print(f"""
    ██████╗████████╗ ████████╗██╗  ██╗
   ██╔════╝██╔════╝  ╚══██╔══╝██║  ██║
   ██║     ███████╗     ██║   ███████║
   ██║     ╚════██║     ██║   ██╔══██║
   ╚██████╗███████║     ██║   ██║  ██║
    ╚═════╝╚══════╝     ╚═╝   ╚═╝  ╚═╝
    """)
    
    print(f"[*] Starting CyberSleuth Pro scan against: {args.target}")
    print(f"[*] Utilizing {THREADS} threads across {cpu_count()} CPU cores")
    print("[*] Beginning comprehensive OSINT gathering and vulnerability scanning...\n")
    
    start_time = time.time()
    sleuth = CyberSleuth(args.target)
    results = sleuth.run_full_scan()
    
    # Display summary
    print("\n[+] Scan Summary:")
    print(f"  - Target IP: {results.get('ip_address', 'N/A')}")
    print(f"  - Domain Info: {len(results['domain_info'])} records")
    print(f"  - Subdomains Found: {len(results['subdomains'])}")
    print(f"  - Open Ports: {len(results['ports'])}")
    print(f"  - Technologies: {len(results['technologies'])} detected")
    print(f"  - Emails Collected: {len(results['emails'])}")
    print(f"  - Phone Numbers: {len(results['phone_numbers'])}")
    print(f"  - Sensitive Files: {len(results['files'])} found")
    print(f"  - Vulnerabilities: {len(results['vulnerabilities'])} detected")
    print(f"  - Scan Duration: {results['scan_time']:.2f} seconds")
    
    # Display vulnerabilities if found
    if results['vulnerabilities']:
        print("\n[!] VULNERABILITIES FOUND:")
        for i, vuln in enumerate(results['vulnerabilities'], 1):
            print(f"\n{i}. {vuln['name']} ({vuln['severity']})")
            print(f"   Description: {vuln['description']}")
            print(f"   Solution: {vuln['solution']}")
    
    # Save results
    if args.output:
        with open(args.output, 'w') as f:
            json.dump(results, f, indent=4)
        print(f"\n[+] Results saved to {args.output}")
    
    print("\n[!] Scan complete. Always use this tool ethically and with proper authorization.")

if __name__ == "__main__":
    main()
