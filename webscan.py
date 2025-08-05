#!/usr/bin/env python3
import os
import sys
import requests
from bs4 import BeautifulSoup
import socket
import whois
import dns.resolver
import argparse
from datetime import datetime
import time
import json
from urllib.parse import urlparse
import nmap
import sqlite3
from concurrent.futures import ThreadPoolExecutor
import re
from colorama import init, Fore, Style
import readline  # For better input handling

# Initialize colorama
init(autoreset=True)

# Banner
def banner():
    print(Fore.CYAN + r"""
     __      __   _______   _______   _______   _______   __   __ 
    |  |    |  | |       | |       | |       | |       | |  | |  |
    |  |    |  | |  _____| |  _____| |    ___| |    ___| |  |_|  |
    |  |    |  | | |_____  | |_____  |   |___  |   |___  |       |
    |  |    |  | |_____  | |_____  | |    ___| |    ___| |       |
    |  |___ |  |  _____| |  _____| | |   |___  |   |___  |   _   |
    |_______||__| |_______| |_______| |_______| |_______| |__| |__|
    """)
    print(Fore.YELLOW + " " * 15 + "WEBSCAN - Modern Website Scanner")
    print(Fore.YELLOW + " " * 20 + "Version 2.0\n")

# Database for known CMS fingerprints
CMS_FINGERPRINTS = {
    "WordPress": {
        "meta_generator": "WordPress",
        "login_page": "/wp-login.php",
        "files": ["/wp-content/", "/wp-includes/"]
    },
    "Joomla": {
        "meta_generator": "Joomla",
        "login_page": "/administrator",
        "files": ["/media/com_", "/components/com_"]
    },
    "Drupal": {
        "meta_generator": "Drupal",
        "login_page": "/user/login",
        "files": ["/sites/all/", "/misc/drupal.js"]
    },
    "Magento": {
        "meta_generator": "Magento",
        "login_page": "/admin",
        "files": ["/js/mage/", "/skin/frontend/"]
    }
}

# Database types detection patterns
DATABASE_PATTERNS = {
    "MySQL": ["mysql_", "mysqli_", "PDO::MYSQL"],
    "PostgreSQL": ["postgres", "pg_", "PDO::PGSQL"],
    "SQLite": ["sqlite", ".db", ".sqlite"],
    "MongoDB": ["mongodb", "MongoClient"],
    "Microsoft SQL Server": ["sqlsrv_", "mssql_", "PDO::SQLSRV"]
}

# Common admin paths
ADMIN_PATHS = [
    "/admin", "/administrator", "/wp-admin", "/login", "/admin/login",
    "/backend", "/manager", "/panel", "/cpanel", "/webadmin"
]

# Initialize nmap scanner
nm = nmap.PortScanner()

# Database for storing scan results
def init_db():
    conn = sqlite3.connect('webscan.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS scans
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  url TEXT,
                  ip TEXT,
                  cms TEXT,
                  database TEXT,
                  estimated_users INTEGER,
                  scan_date TEXT,
                  ports TEXT,
                  vulnerabilities TEXT)''')
    conn.commit()
    conn.close()

# Save scan results to database
def save_scan(url, ip, cms, database, estimated_users, ports, vulnerabilities):
    conn = sqlite3.connect('webscan.db')
    c = conn.cursor()
    c.execute("INSERT INTO scans (url, ip, cms, database, estimated_users, scan_date, ports, vulnerabilities) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
              (url, ip, cms, database, estimated_users, datetime.now().strftime("%Y-%m-%d %H:%M:%S"), ports, vulnerabilities))
    conn.commit()
    conn.close()

# Get website IP
def get_ip(url):
    try:
        domain = urlparse(url).netloc
        ip = socket.gethostbyname(domain)
        return ip
    except Exception as e:
        print(Fore.RED + f"[!] Error getting IP: {e}")
        return None

# Get WHOIS information
def get_whois(url):
    try:
        domain = urlparse(url).netloc
        w = whois.whois(domain)
        return w
    except Exception as e:
        print(Fore.RED + f"[!] Error getting WHOIS: {e}")
        return None

# Check if URL is valid
def is_valid_url(url):
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])
    except ValueError:
        return False

# Get server headers
def get_headers(url):
    try:
        response = requests.head(url, timeout=10, allow_redirects=True)
        return response.headers
    except Exception as e:
        print(Fore.RED + f"[!] Error getting headers: {e}")
        return None

# Detect CMS
def detect_cms(url):
    try:
        response = requests.get(url, timeout=10)
        soup = BeautifulSoup(response.text, 'html.parser')
        
        # Check meta generator tag
        meta_generator = soup.find('meta', attrs={'name': 'generator'})
        if meta_generator:
            for cms, data in CMS_FINGERPRINTS.items():
                if data['meta_generator'].lower() in meta_generator.get('content', '').lower():
                    return cms
        
        # Check for specific files
        for cms, data in CMS_FINGERPRINTS.items():
            for path in data['files']:
                check_url = url + path if url.endswith('/') else url + '/' + path
                try:
                    r = requests.head(check_url, timeout=5)
                    if r.status_code == 200:
                        return cms
                except:
                    continue
        
        # Check for login pages
        for cms, data in CMS_FINGERPRINTS.items():
            check_url = url + data['login_page'] if url.endswith('/') else url + '/' + data['login_page']
            try:
                r = requests.head(check_url, timeout=5)
                if r.status_code == 200:
                    return cms
            except:
                continue
        
        return "Unknown"
    except Exception as e:
        print(Fore.RED + f"[!] Error detecting CMS: {e}")
        return "Unknown"

# Detect database
def detect_database(url):
    try:
        response = requests.get(url, timeout=10)
        content = response.text.lower()
        
        for db_type, patterns in DATABASE_PATTERNS.items():
            for pattern in patterns:
                if pattern.lower() in content:
                    return db_type
        
        # Check common database files
        common_db_files = [
            "/wp-config.php", "/configuration.php", 
            "/app/etc/local.xml", "/settings.php"
        ]
        
        for file in common_db_files:
            check_url = url + file if url.endswith('/') else url + '/' + file
            try:
                r = requests.get(check_url, timeout=5)
                if r.status_code == 200:
                    content = r.text.lower()
                    for db_type, patterns in DATABASE_PATTERNS.items():
                        for pattern in patterns:
                            if pattern.lower() in content:
                                return db_type
            except:
                continue
        
        return "Unknown"
    except Exception as e:
        print(Fore.RED + f"[!] Error detecting database: {e}")
        return "Unknown"

# Estimate registered users
def estimate_users(url, cms):
    try:
        if cms == "WordPress":
            # Try to access author pages
            check_url = url + "/?author=1" if url.endswith('/') else url + '/?author=1'
            r = requests.get(check_url, allow_redirects=True, timeout=10)
            if r.history:
                # WordPress redirects author pages to their usernames
                # The highest author ID that doesn't redirect to homepage is the user count
                low = 1
                high = 10000
                last_valid = 0
                
                while low <= high:
                    mid = (low + high) // 2
                    check_url = url + f"/?author={mid}" if url.endswith('/') else url + f'/?author={mid}'
                    r = requests.get(check_url, allow_redirects=False, timeout=5)
                    
                    if r.status_code == 301:
                        last_valid = mid
                        low = mid + 1
                    else:
                        high = mid - 1
                
                return last_valid
                
        elif cms == "Joomla":
            # Joomla user estimation is tricky, we'll check registration component
            check_url = url + "/component/users/?view=registration" if url.endswith('/') else url + '/component/users/?view=registration'
            r = requests.get(check_url, timeout=10)
            if r.status_code == 200:
                # Very rough estimation based on registration form existence
                return "100+ (Registration open)"
            else:
                return "Unknown (Registration closed)"
        
        elif cms == "Drupal":
            # Drupal user estimation
            check_url = url + "/user" if url.endswith('/') else url + '/user'
            r = requests.get(check_url, timeout=10)
            if r.status_code == 200:
                soup = BeautifulSoup(r.text, 'html.parser')
                user_links = soup.find_all('a', href=re.compile(r'/user/\d+'))
                if user_links:
                    max_id = 0
                    for link in user_links:
                        match = re.search(r'/user/(\d+)', link['href'])
                        if match:
                            user_id = int(match.group(1))
                            if user_id > max_id:
                                max_id = user_id
                    return max_id
        
        return "Unknown"
    except Exception as e:
        print(Fore.RED + f"[!] Error estimating users: {e}")
        return "Unknown"

# Scan ports
def scan_ports(ip, ports="80,443,21,22,3306,5432,8080"):
    try:
        print(Fore.YELLOW + f"\n[~] Scanning ports {ports} on {ip}...")
        nm.scan(hosts=ip, ports=ports)
        open_ports = []
        for host in nm.all_hosts():
            for proto in nm[host].all_protocols():
                lport = nm[host][proto].keys()
                for port in sorted(lport):
                    if nm[host][proto][port]['state'] == 'open':
                        open_ports.append(f"{port}/{proto}")
        
        return ", ".join(open_ports) if open_ports else "No open ports found"
    except Exception as e:
        print(Fore.RED + f"[!] Error scanning ports: {e}")
        return "Port scan failed"

# Check for common vulnerabilities
def check_vulnerabilities(url, cms):
    vulnerabilities = []
    try:
        if cms == "WordPress":
            # Check for outdated WordPress
            check_url = url + "/readme.html" if url.endswith('/') else url + '/readme.html'
            r = requests.get(check_url, timeout=10)
            if r.status_code == 200 and "WordPress" in r.text:
                vulnerabilities.append("WordPress version exposed in readme.html")
            
            # Check for XML-RPC
            check_url = url + "/xmlrpc.php" if url.endswith('/') else url + '/xmlrpc.php'
            r = requests.get(check_url, timeout=10)
            if r.status_code == 200 and "XML-RPC server accepts POST requests only" in r.text:
                vulnerabilities.append("XML-RPC enabled (potential DDoS vulnerability)")
        
        elif cms == "Joomla":
            # Check for administrator directory
            check_url = url + "/administrator" if url.endswith('/') else url + '/administrator'
            r = requests.get(check_url, timeout=10)
            if r.status_code == 200 and "Joomla" in r.text:
                vulnerabilities.append("Joomla administrator panel accessible")
        
        # Check for common files
        common_files = [
            "/.env", "/.git/config", "/.htaccess", "/phpinfo.php",
            "/test.php", "/config.php", "/backup.zip"
        ]
        
        for file in common_files:
            check_url = url + file if url.endswith('/') else url + '/' + file
            try:
                r = requests.get(check_url, timeout=5)
                if r.status_code == 200:
                    vulnerabilities.append(f"Sensitive file exposed: {file}")
            except:
                continue
        
        return ", ".join(vulnerabilities) if vulnerabilities else "No obvious vulnerabilities found"
    except Exception as e:
        print(Fore.RED + f"[!] Error checking vulnerabilities: {e}")
        return "Vulnerability check failed"

# Check admin panels
def check_admin_panels(url):
    found = []
    try:
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = []
            for path in ADMIN_PATHS:
                check_url = url + path if url.endswith('/') else url + '/' + path
                futures.append(executor.submit(check_admin_panel, check_url))
            
            for future in futures:
                result = future.result()
                if result:
                    found.append(result)
        
        return ", ".join(found) if found else "No admin panels found"
    except Exception as e:
        print(Fore.RED + f"[!] Error checking admin panels: {e}")
        return "Admin panel check failed"

def check_admin_panel(url):
    try:
        r = requests.head(url, timeout=5)
        if r.status_code == 200:
            return url
        return None
    except:
        return None

# Get DNS records
def get_dns_records(domain):
    records = {}
    try:
        # A records
        answers = dns.resolver.resolve(domain, 'A')
        records['A'] = [str(r) for r in answers]
    except:
        pass
    
    try:
        # MX records
        answers = dns.resolver.resolve(domain, 'MX')
        records['MX'] = [str(r.exchange) for r in answers]
    except:
        pass
    
    try:
        # NS records
        answers = dns.resolver.resolve(domain, 'NS')
        records['NS'] = [str(r) for r in answers]
    except:
        pass
    
    try:
        # TXT records
        answers = dns.resolver.resolve(domain, 'TXT')
        records['TXT'] = [str(r) for r in answers]
    except:
        pass
    
    return records

# Main scan function
def scan_website(url):
    if not is_valid_url(url):
        print(Fore.RED + "[!] Invalid URL. Please include http:// or https://")
        return
    
    print(Fore.GREEN + f"\n[+] Starting scan for {url}")
    
    start_time = time.time()
    
    # Get basic info
    ip = get_ip(url)
    if ip:
        print(Fore.GREEN + f"[+] IP Address: {ip}")
    
    headers = get_headers(url)
    if headers:
        print(Fore.GREEN + f"[+] Server: {headers.get('Server', 'Unknown')}")
        print(Fore.GREEN + f"[+] X-Powered-By: {headers.get('X-Powered-By', 'Unknown')}")
    
    # Get WHOIS info
    whois_info = get_whois(url)
    if whois_info:
        print(Fore.GREEN + f"[+] Domain registrar: {whois_info.registrar or 'Unknown'}")
        print(Fore.GREEN + f"[+] Creation date: {whois_info.creation_date or 'Unknown'}")
    
    # Get DNS records
    domain = urlparse(url).netloc
    dns_records = get_dns_records(domain)
    if dns_records:
        print(Fore.GREEN + "[+] DNS Records:")
        for record_type, values in dns_records.items():
            print(Fore.GREEN + f"    {record_type}: {', '.join(values)}")
    
    # Detect CMS
    cms = detect_cms(url)
    print(Fore.GREEN + f"[+] CMS: {cms}")
    
    # Detect database
    database = detect_database(url)
    print(Fore.GREEN + f"[+] Database: {database}")
    
    # Estimate users
    estimated_users = estimate_users(url, cms)
    print(Fore.GREEN + f"[+] Estimated registered users: {estimated_users}")
    
    # Scan ports
    if ip:
        open_ports = scan_ports(ip)
        print(Fore.GREEN + f"[+] Open ports: {open_ports}")
    else:
        open_ports = "Unknown"
    
    # Check vulnerabilities
    vulnerabilities = check_vulnerabilities(url, cms)
    print(Fore.GREEN + f"[+] Vulnerabilities: {vulnerabilities}")
    
    # Check admin panels
    admin_panels = check_admin_panels(url)
    print(Fore.GREEN + f"[+] Admin panels: {admin_panels}")
    
    # Save to database
    save_scan(url, ip or "", cms, database, str(estimated_users), open_ports, vulnerabilities)
    
    end_time = time.time()
    print(Fore.GREEN + f"\n[+] Scan completed in {end_time - start_time:.2f} seconds")

# Interactive mode
def interactive_mode():
    while True:
        print(Fore.CYAN + "\nWEBSCAN Menu:")
        print(Fore.CYAN + "1. Scan a website")
        print(Fore.CYAN + "2. View scan history")
        print(Fore.CYAN + "3. Exit")
        
        choice = input(Fore.YELLOW + "\n[?] Select an option (1-3): ").strip()
        
        if choice == "1":
            url = input(Fore.YELLOW + "[?] Enter URL to scan (include http:// or https://): ").strip()
            scan_website(url)
        elif choice == "2":
            view_scan_history()
        elif choice == "3":
            print(Fore.YELLOW + "[+] Exiting WEBSCAN. Goodbye!")
            sys.exit(0)
        else:
            print(Fore.RED + "[!] Invalid choice. Please try again.")

# View scan history
def view_scan_history():
    try:
        conn = sqlite3.connect('webscan.db')
        c = conn.cursor()
        c.execute("SELECT * FROM scans ORDER BY scan_date DESC LIMIT 10")
        scans = c.fetchall()
        conn.close()
        
        if not scans:
            print(Fore.YELLOW + "[!] No scan history found")
            return
        
        print(Fore.CYAN + "\nLast 10 scans:")
        for scan in scans:
            print(Fore.GREEN + f"\nID: {scan[0]}")
            print(Fore.GREEN + f"URL: {scan[1]}")
            print(Fore.GREEN + f"IP: {scan[2]}")
            print(Fore.GREEN + f"CMS: {scan[3]}")
            print(Fore.GREEN + f"Database: {scan[4]}")
            print(Fore.GREEN + f"Estimated users: {scan[5]}")
            print(Fore.GREEN + f"Scan date: {scan[6]}")
            print(Fore.GREEN + f"Open ports: {scan[7]}")
            print(Fore.GREEN + f"Vulnerabilities: {scan[8]}")
        
        print()
    except Exception as e:
        print(Fore.RED + f"[!] Error viewing scan history: {e}")

# Main function
def main():
    # Initialize database
    init_db()
    
    # Show banner
    banner()
    
    # Check for command line arguments
    parser = argparse.ArgumentParser(description='WEBSCAN - Modern Website Scanner')
    parser.add_argument('-u', '--url', help='URL to scan')
    args = parser.parse_args()
    
    if args.url:
        scan_website(args.url)
    else:
        interactive_mode()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(Fore.RED + "\n[!] Scan interrupted by user")
        sys.exit(1)
