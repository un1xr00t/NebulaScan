import socket
import concurrent.futures
import ipaddress
import struct
import os
import sys
import random
import time
import gzip
import json
import requests
import sqlite3
import argparse
import logging
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
from scapy.all import sr1, IP, TCP
from colorama import init, Fore, Back, Style

# Global variable for database path
CVE_DB_PATH = 'cve_database.db'
VERBOSE_MODE = False
SCAN_DELAY = 0.1
USE_RANDOMIZED_PORTS = False

def main_menu():
    while True:
        print("\nNetwork Vulnerability Scanner")
        print("----------------------------")
        print("1. Scanning")
        print("2. Vulnerability Assessment")
        print("3. Reporting and Output")
        print("4. User Experience")
        print("5. Advanced Features")
        print("0. Exit")

        choice = input("Enter your choice: ")

        if choice == '1':
            scanning_menu()
        elif choice == '2':
            vulnerability_menu()
        elif choice == '3':
            reporting_menu()
        elif choice == '4':
            user_experience_menu()
        elif choice == '5':
            advanced_features_menu()
        elif choice == '0':
            print("Exiting...")
            break
        else:
            print("Invalid choice. Please try again.")
            
def setup_logging():
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler("nebulascan.log"),
            logging.StreamHandler()
        ]
    )

def scanning_menu():
    while True:
        print("\nScanning Options")
        print("----------------")
        print("1. TCP Port Scan")
        print("2. UDP Port Scan")
        print("3. SYN Scan")
        print("4. Service Version Detection")
        print("5. OS Detection")
        print("6. Scan Speed Control")
        print("7. Randomized Port Order")
        print("0. Back to Main Menu")

        choice = input("Enter your choice: ")

        if choice == '1':
            target = input("Enter target IP address or hostname: ")
            start_port = int(input("Enter start port (1-65535): "))
            end_port = int(input("Enter end port (1-65535): "))
            tcp_port_scan(target, start_port, end_port)  # Pass the required arguments
        elif choice == '2':
            udp_port_scan()
        elif choice == '3':
            syn_scan()
        elif choice == '4':
            service_version_detection()
        elif choice == '5':
            os_detection()
        elif choice == '6':
            scan_speed_control()
        elif choice == '7':
            randomized_port_order()
        elif choice == '0':
            break
        else:
            print("Invalid choice. Please try again.")

def vulnerability_menu():
    while True:
        print("\nVulnerability Assessment Options")
        print("--------------------------------")
        print("1. CVE Database Integration")
        print("2. Vulnerability Severity Scoring")
        print("3. Exploitability Checks")
        print("0. Back to Main Menu")

        choice = input("Enter your choice: ")

        if choice == '1':
            cve_database_integration()
        elif choice == '2':
            vulnerability_severity_scoring()
        elif choice == '3':
            exploitability_checks()
        elif choice == '0':
            break
        else:
            print("Invalid choice. Please try again.")

def reporting_menu():
    while True:
        print("\nReporting and Output Options")
        print("-----------------------------")
        print("1. HTML Report Generation")
        print("2. JSON Output")
        print("3. Verbose Mode")
        print("4. Progress Bar")
        print("0. Back to Main Menu")

        choice = input("Enter your choice: ")

        if choice == '1':
            html_report_generation()
        elif choice == '2':
            json_output()
        elif choice == '3':
            verbose_mode()
        elif choice == '4':
            progress_bar()
        elif choice == '0':
            break
        else:
            print("Invalid choice. Please try again.")

def user_experience_menu():
    while True:
        print("\nUser Experience Options")
        print("------------------------")
        print("1. Command-Line Interface Improvements")
        print("2. Configuration File")
        print("3. Target List Import")
        print("0. Back to Main Menu")

        choice = input("Enter your choice: ")

        if choice == '1':
            cli_improvements()
        elif choice == '2':
            configuration_file()
        elif choice == '3':
            target_list_import()
        elif choice == '0':
            break
        else:
            print("Invalid choice. Please try again.")

def advanced_features_menu():
    while True:
        print("\nAdvanced Features Options")
        print("-------------------------")
        print("1. Web Application Scanning")
        print("2. Network Mapping")
        print("3. Firewall/IDS Evasion")
        print("4. Script Execution")
        print("5. Multithreading")
        print("6. Proxy Support")
        print("7. Cloud Integration")
        print("8. API Integration")
        print("9. Scheduled Scans")
        print("0. Back to Main Menu")

        choice = input("Enter your choice: ")

        if choice == '1':
            web_application_scanning()
        elif choice == '2':
            network_mapping()
        elif choice == '3':
            firewall_ids_evasion()
        elif choice == '4':
            script_execution()
        elif choice == '5':
            multithreading()
        elif choice == '6':
            proxy_support()
        elif choice == '7':
            cloud_integration()
        elif choice == '8':
            api_integration()
        elif choice == '9':
            scheduled_scans()
        elif choice == '0':
            break
        else:
            print("Invalid choice. Please try again.")

# Scanning functions
def tcp_port_scan():
    target = input("Enter target IP address or hostname: ")
    start_port = int(input("Enter start port (1-65535): "))
    end_port = int(input("Enter end port (1-65535): "))
    
    try:
        # Resolve hostname to IP address
        ip = socket.gethostbyname(target)
        verbose_print(f"Resolved {target} to IP: {ip}")
        
        print(f"\nScanning {target} ({ip}) for open TCP ports...")
        
        # Validate IP address
        ipaddress.ip_address(ip)
        
        # Validate port range
        if not 1 <= start_port <= end_port <= 65535:
            raise ValueError("Invalid port range")
        
        open_ports = []
        total_ports = end_port - start_port + 1
        
        for i, port in enumerate(range(start_port, end_port + 1), 1):
            verbose_print(f"Scanning port {port}")
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((ip, port))
            if result == 0:
                open_ports.append(port)
                print(f"Port {port}: Open")
            sock.close()
            
            # Apply scan delay
            apply_scan_delay()
            
            # Update progress bar
            progress_bar(i, total_ports, prefix='Scan Progress:', suffix='Complete', length=50)
        
        print("\nScan complete!")
        if open_ports:
            print("\nOpen ports:")
            for port in open_ports:
                print(f"Port {port}: Open")
        else:
            print("\nNo open ports found.")
        
        verbose_print(f"Scan completed. Found {len(open_ports)} open port(s).")
    
    except socket.gaierror:
        print("Error: Hostname could not be resolved. Please enter a valid hostname or IP address.")
    except ValueError as e:
        print(f"Error: {e}")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
    finally:
        print("Scan finished.")

# Make sure these functions are defined elsewhere in your code:
# verbose_print(message)
# progress_bar(iteration, total, prefix='', suffix='', decimals=1, length=50, fill='█', print_end="\r")
# apply_scan_delay()

def scan_single_port(ip, port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(1)
        result = sock.connect_ex((ip, port))
        if result == 0:
            return port
    return None

def scan_ports(ip, start_port, end_port):
    open_ports = []
    total_ports = end_port - start_port + 1
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
        future_to_port = {executor.submit(scan_single_port, ip, port): port 
                          for port in range(start_port, end_port + 1)}
        
        completed = 0
        for future in concurrent.futures.as_completed(future_to_port):
            port = future_to_port[future]
            try:
                result = future.result()
                if result:
                    open_ports.append(result)
            except Exception as e:
                print(f"Error scanning port {port}: {e}")
            
            completed += 1
            progress = (completed / total_ports) * 100
            print(f"\rProgress: {progress:.1f}% ", end="", flush=True)
    
    print("\nScan complete!")
    return sorted(open_ports)

def udp_port_scan():
    target = input("Enter target IP address or hostname: ")
    start_port = int(input("Enter start port (1-65535): "))
    end_port = int(input("Enter end port (1-65535): "))
    
    try:
        ip = socket.gethostbyname(target)
        print(f"\nScanning {target} ({ip}) for open UDP ports...")
        
        ipaddress.ip_address(ip)
        
        if not 1 <= start_port <= end_port <= 65535:
            raise ValueError("Invalid port range")
        
        open_ports = scan_udp_ports(ip, start_port, end_port)
        
        if open_ports:
            print("\nPotentially open UDP ports:")
            for port in open_ports:
                print(f"Port {port}: Potentially Open")
        else:
            print("\nNo open UDP ports found.")
    
    except socket.gaierror:
        print("Hostname could not be resolved. Please enter a valid hostname or IP address.")
    except ValueError as e:
        print(f"Error: {e}")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")

def scan_single_udp_port(ip, port):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(1)
        message = b"Hello, server"
        try:
            sock.sendto(message, (ip, port))
            data, _ = sock.recvfrom(1024)
            return port
        except socket.timeout:
            return None  # Assume closed or filtered
        except socket.error:
            return port  # Potentially open (ICMP unreachable error)

def scan_udp_ports(ip, start_port, end_port):
    open_ports = []
    total_ports = end_port - start_port + 1
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
        future_to_port = {executor.submit(scan_single_udp_port, ip, port): port 
                          for port in range(start_port, end_port + 1)}
        
        completed = 0
        for future in concurrent.futures.as_completed(future_to_port):
            port = future_to_port[future]
            try:
                result = future.result()
                if result:
                    open_ports.append(result)
            except Exception as e:
                print(f"Error scanning port {port}: {e}")
            
            completed += 1
            progress = (completed / total_ports) * 100
            print(f"\rProgress: {progress:.1f}% ", end="", flush=True)
    
    print("\nScan complete!")
    return sorted(open_ports)


def syn_scan():
    if os.geteuid() != 0:
        print("SYN scan requires root privileges. Please run the script as root or with sudo.")
        return

    target = input("Enter target IP address or hostname: ")
    start_port = int(input("Enter start port (1-65535): "))
    end_port = int(input("Enter end port (1-65535): "))
    
    try:
        ip = socket.gethostbyname(target)
        print(f"\nPerforming SYN scan on {target} ({ip})...")
        
        if not 1 <= start_port <= end_port <= 65535:
            raise ValueError("Invalid port range")
        
        open_ports = perform_syn_scan(ip, start_port, end_port)
        
        if open_ports:
            print("\nOpen ports:")
            for port in open_ports:
                print(f"Port {port}: Open")
        else:
            print("\nNo open ports found.")
    
    except socket.gaierror:
        print("Hostname could not be resolved. Please enter a valid hostname or IP address.")
    except ValueError as e:
        print(f"Error: {e}")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")

def syn_scan_port(ip, port):
    try:
        packet = IP(dst=ip)/TCP(dport=port, flags="S")
        response = sr1(packet, timeout=1, verbose=0)
        
        if response and response.haslayer(TCP):
            if response[TCP].flags == 0x12:  # SYN-ACK
                send_rst = IP(dst=ip)/TCP(dport=port, flags="R")
                sr1(send_rst, timeout=1, verbose=0)
                return port
            elif response[TCP].flags == 0x14:  # RST-ACK
                return None
        return None
    except Exception as e:
        print(f"Error scanning port {port}: {e}")
        return None

def perform_syn_scan(ip, start_port, end_port):
    open_ports = []
    total_ports = end_port - start_port + 1
    
    with ThreadPoolExecutor(max_workers=100) as executor:
        future_to_port = {executor.submit(syn_scan_port, ip, port): port 
                          for port in range(start_port, end_port + 1)}
        
        completed = 0
        for future in concurrent.futures.as_completed(future_to_port):
            port = future_to_port[future]
            try:
                result = future.result()
                if result:
                    open_ports.append(result)
            except Exception as e:
                print(f"Error scanning port {port}: {e}")
            
            completed += 1
            progress = (completed / total_ports) * 100
            print(f"\rProgress: {progress:.1f}% ", end="", flush=True)
    
    print("\nScan complete!")
    return sorted(open_ports)

def service_version_detection():
    target = input("Enter target IP address or hostname: ")
    port = int(input("Enter the port to scan: "))
    
    try:
        ip = socket.gethostbyname(target)
        print(f"\nDetecting service on {target} ({ip}) port {port}...")
        
        service_info = detect_service(ip, port)
        
        if service_info:
            print(f"Service detected on port {port}:")
            print(f"Name: {service_info['name']}")
            print(f"Version: {service_info['version']}")
        else:
            print(f"No service information detected on port {port}")
    
    except socket.gaierror:
        print("Hostname could not be resolved. Please enter a valid hostname or IP address.")
    except ValueError:
        print("Invalid port number. Please enter a number between 1 and 65535.")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")

def detect_service(ip, port):
    try:
        with socket.create_connection((ip, port), timeout=5) as sock:
            sock.send(b"GET / HTTP/1.0\r\nHost: " + ip.encode() + b"\r\n\r\n")
            response = sock.recv(1024).decode('utf-8', errors='ignore')
            
            # Check for HTTP response
            if response.startswith("HTTP/"):
                server = re.search(r"Server: (.+)", response)
                if server:
                    return {"name": "HTTP", "version": server.group(1)}
                return {"name": "HTTP", "version": "Unknown"}
            
            # Check for SSH
            elif response.startswith("SSH-"):
                version = response.split()[0].split("-")[1]
                return {"name": "SSH", "version": version}
            
            # Check for FTP
            elif response.startswith("220"):
                version = response.split()[1]
                return {"name": "FTP", "version": version}
            
            # Add more protocol checks here
            
            else:
                return {"name": "Unknown", "version": "Unknown"}
    
    except socket.timeout:
        return None
    except Exception as e:
        print(f"Error detecting service: {e}")
        return None

def os_detection():
    target = input("Enter target IP address or hostname: ")
    
    try:
        ip = socket.gethostbyname(target)
        print(f"\nAttempting OS detection on {target} ({ip})...")
        
        os_info = detect_os(ip)
        
        if os_info:
            print(f"Detected OS: {os_info}")
        else:
            print("Unable to determine the OS.")
    
    except socket.gaierror:
        print("Hostname could not be resolved. Please enter a valid hostname or IP address.")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")

def detect_os(ip):
    # Test 1: TCP Window Size
    window_size = test_tcp_window_size(ip)
    
    # Test 2: TTL (Time To Live)
    ttl = test_ttl(ip)
    
    # Test 3: TCP Options
    tcp_options = test_tcp_options(ip)
    
    # Simple OS guessing based on the results
    if window_size == 64240 and ttl >= 64 and ttl <= 128:
        return "Likely Linux"
    elif window_size == 8192 and ttl >= 128 and ttl <= 255:
        return "Likely Windows"
    elif window_size == 65535 and ttl >= 48 and ttl <= 64:
        return "Likely FreeBSD/OpenBSD"
    elif window_size == 65535 and ttl >= 64 and ttl <= 255:
        return "Likely Solaris"
    else:
        return "Unknown OS"

def test_tcp_window_size(ip):
    try:
        sport = random.randint(1024, 65535)
        packet = IP(dst=ip) / TCP(sport=sport, dport=80, flags="S")
        response = sr1(packet, timeout=2, verbose=0)
        
        if response and response.haslayer(TCP):
            return response[TCP].window
    except:
        pass
    return None

def test_ttl(ip):
    try:
        packet = IP(dst=ip) / ICMP()
        response = sr1(packet, timeout=2, verbose=0)
        
        if response and response.haslayer(IP):
            return response[IP].ttl
    except:
        pass
    return None

def test_tcp_options(ip):
    try:
        sport = random.randint(1024, 65535)
        packet = IP(dst=ip) / TCP(sport=sport, dport=80, flags="S")
        response = sr1(packet, timeout=2, verbose=0)
        
        if response and response.haslayer(TCP):
            return response[TCP].options
    except:
        pass
    return None

# Global variable to store the current scan delay
SCAN_DELAY = 0.1  # Default delay of 0.1 seconds between port scans

def scan_speed_control():
    global SCAN_DELAY
    print("\nScan Speed Control")
    print("------------------")
    print(f"Current scan delay: {SCAN_DELAY} seconds")
    
    while True:
        choice = input("\nEnter new scan delay in seconds (0.01 - 1.0), or 'b' to go back: ")
        
        if choice.lower() == 'b':
            break
        
        try:
            new_delay = float(choice)
            if 0.01 <= new_delay <= 1.0:
                SCAN_DELAY = new_delay
                print(f"Scan delay updated to {SCAN_DELAY} seconds")
                break
            else:
                print("Please enter a value between 0.01 and 1.0")
        except ValueError:
            print("Invalid input. Please enter a number or 'b'")

def apply_scan_delay():
    time.sleep(SCAN_DELAY)

# Update your port scanning functions to use the apply_scan_delay function
def scan_single_tcp_port(ip, port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(1)
        result = sock.connect_ex((ip, port))
        apply_scan_delay()  # Add this line to control scan speed
        if result == 0:
            return port
    return None

# Similarly, update other scanning functions (UDP, SYN) to use apply_scan_delay()

def randomized_port_order():
    global USE_RANDOMIZED_PORTS
    print("\nRandomized Port Order")
    print("---------------------")
    
    while True:
        print(f"Randomized port scanning is currently: {'ENABLED' if USE_RANDOMIZED_PORTS else 'DISABLED'}")
        choice = input("Enter '1' to enable, '2' to disable, or '0' to go back: ")
        
        if choice == '1':
            USE_RANDOMIZED_PORTS = True
            print("Randomized port scanning has been enabled.")
        elif choice == '2':
            USE_RANDOMIZED_PORTS = False
            print("Randomized port scanning has been disabled.")
        elif choice == '0':
            break
        else:
            print("Invalid choice. Please try again.")

# Vulnerability Assessment functions
def update_cve_database():
    print("Updating CVE database...")
    nvd_url = "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-recent.json.gz"
    
    try:
        response = requests.get(nvd_url)
        response.raise_for_status()
        
        json_content = gzip.decompress(response.content)
        cve_data = json.loads(json_content)
        
        conn = sqlite3.connect(CVE_DB_PATH)
        cursor = conn.cursor()
        
        cursor.execute('''CREATE TABLE IF NOT EXISTS cve_entries
                          (id TEXT PRIMARY KEY, description TEXT, cvss_score REAL, 
                           affected_products TEXT, last_modified_date TEXT)''')
        
        for item in cve_data['CVE_Items']:
            cve_id = item['cve']['CVE_data_meta']['ID']
            description = item['cve']['description']['description_data'][0]['value']
            cvss_score = item['impact']['baseMetricV2']['cvssV2']['baseScore'] if 'impact' in item else None
            affected_products = json.dumps([prod['product']['product_data'][0]['product_name'] 
                                            for prod in item['cve']['affects']['vendor']['vendor_data']])
            last_modified_date = item['lastModifiedDate']
            
            cursor.execute('''INSERT OR REPLACE INTO cve_entries 
                              (id, description, cvss_score, affected_products, last_modified_date) 
                              VALUES (?, ?, ?, ?, ?)''', 
                           (cve_id, description, cvss_score, affected_products, last_modified_date))
        
        conn.commit()
        conn.close()
        
        print("CVE database updated successfully.")
    except Exception as e:
        print(f"Error updating CVE database: {e}")

def view_database_status():
    if not os.path.exists(CVE_DB_PATH):
        print("CVE database has not been created yet.")
        return
    
    conn = sqlite3.connect(CVE_DB_PATH)
    cursor = conn.cursor()
    
    cursor.execute("SELECT COUNT(*) FROM cve_entries")
    total_entries = cursor.fetchone()[0]
    
    cursor.execute("SELECT MAX(last_modified_date) FROM cve_entries")
    last_update = cursor.fetchone()[0]
    
    conn.close()
    
    print(f"\nCVE Database Status:")
    print(f"Total entries: {total_entries}")
    print(f"Last updated: {last_update}")

def search_vulnerabilities(search_term):
    conn = sqlite3.connect(CVE_DB_PATH)
    cursor = conn.cursor()
    
    cursor.execute('''SELECT * FROM cve_entries 
                      WHERE id LIKE ? OR description LIKE ? OR affected_products LIKE ?''', 
                   (f'%{search_term}%', f'%{search_term}%', f'%{search_term}%'))
    
    results = cursor.fetchall()
    
    conn.close()
    
    if results:
        print(f"\nFound {len(results)} matching vulnerabilities:")
        for result in results:
            print(f"\nCVE ID: {result[0]}")
            print(f"Description: {result[1]}")
            print(f"CVSS Score: {result[2]}")
            print(f"Affected Products: {result[3]}")
            print(f"Last Modified: {result[4]}")
    else:
        print("No matching vulnerabilities found.")

def cve_database_integration():
    while True:
        print("\nCVE Database Integration")
        print("------------------------")
        print("1. Update CVE Database")
        print("2. View Database Status")
        print("3. Search Vulnerabilities")
        print("0. Back to Vulnerability Menu")

        choice = input("Enter your choice: ")

        if choice == '1':
            update_cve_database()
        elif choice == '2':
            view_database_status()
        elif choice == '3':
            search_term = input("Enter a product name or CVE ID to search for: ")
            search_vulnerabilities(search_term)
        elif choice == '0':
            break
        else:
            print("Invalid choice. Please try again.")

def vulnerability_severity_scoring(cvss_score, cvss_vector=None):
    def parse_cvss_vector(vector):
        if not vector:
            return {}
        return dict(item.split(":") for item in vector.split("/")[1:])

    def get_severity_category(score):
        if score is None:
            return "Unknown"
        elif score >= 9.0:
            return "Critical"
        elif score >= 7.0:
            return "High"
        elif score >= 4.0:
            return "Medium"
        elif score >= 0.1:
            return "Low"
        else:
            return "None"

    def get_exploitability_subscore(vector_data):
        weights = {
            'AV': {'N': 0.85, 'A': 0.62, 'L': 0.55, 'P': 0.2},
            'AC': {'L': 0.77, 'H': 0.44},
            'PR': {'N': 0.85, 'L': 0.62, 'H': 0.27},
            'UI': {'N': 0.85, 'R': 0.62}
        }
        
        exploitability = 8.22
        for metric in ['AV', 'AC', 'PR', 'UI']:
            if metric in vector_data:
                exploitability *= weights[metric].get(vector_data[metric], 1)
        
        return round(exploitability, 1)

    def get_impact_subscore(vector_data):
        weights = {
            'C': {'H': 0.56, 'L': 0.22, 'N': 0},
            'I': {'H': 0.56, 'L': 0.22, 'N': 0},
            'A': {'H': 0.56, 'L': 0.22, 'N': 0}
        }
        
        impact = 0
        for metric in ['C', 'I', 'A']:
            if metric in vector_data:
                impact += weights[metric].get(vector_data[metric], 0)
        
        impact_score = 6.42 * impact
        return round(impact_score, 1)

    vector_data = parse_cvss_vector(cvss_vector)
    severity_category = get_severity_category(cvss_score)
    
    result = {
        "CVSS Score": cvss_score,
        "Severity": severity_category,
        "Vector String": cvss_vector
    }

    if vector_data:
        result["Exploitability Subscore"] = get_exploitability_subscore(vector_data)
        result["Impact Subscore"] = get_impact_subscore(vector_data)
        result["Attack Vector"] = vector_data.get('AV', 'Unknown')
        result["Attack Complexity"] = vector_data.get('AC', 'Unknown')
        result["Privileges Required"] = vector_data.get('PR', 'Unknown')
        result["User Interaction"] = vector_data.get('UI', 'Unknown')
        result["Scope"] = vector_data.get('S', 'Unknown')
        result["Confidentiality Impact"] = vector_data.get('C', 'Unknown')
        result["Integrity Impact"] = vector_data.get('I', 'Unknown')
        result["Availability Impact"] = vector_data.get('A', 'Unknown')

    return result
    cvss_score = 7.5
    cvss_vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    
    result = vulnerability_severity_scoring(cvss_score, cvss_vector)
    
    print("Vulnerability Severity Assessment:")
    for key, value in result.items():
        print(f"{key}: {value}")

def exploitability_checks(cve_id):
    print(f"Checking exploitability for {cve_id}...")
    
    # Using the Exploit Database API
    url = f"https://exploits.shodan.io/api/search?query={cve_id}"
    headers = {"Accept": "application/json"}
    
    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        data = response.json()
        
        if data['total'] > 0:
            print(f"Found {data['total']} potential exploit(s) for {cve_id}:")
            for exploit in data['matches']:
                print(f"- {exploit['description']}")
                print(f"  Source: {exploit['source']}")
                print(f"  URL: https://exploit-db.com/exploits/{exploit['id']}")
                print()
        else:
            print(f"No known exploits found for {cve_id}")
    
    except requests.exceptions.RequestException as e:
        print(f"Error checking exploitability: {e}")
    except json.JSONDecodeError:
        print("Error parsing response from Exploit Database")

# Example usage in your vulnerability menu
def vulnerability_menu():
    while True:
        print("\nVulnerability Assessment Options")
        print("--------------------------------")
        print("1. CVE Database Integration")
        print("2. Vulnerability Severity Scoring")
        print("3. Exploitability Checks")
        print("0. Back to Main Menu")

        choice = input("Enter your choice: ")

        if choice == '1':
            cve_database_integration()
        elif choice == '2':
            vulnerability_severity_scoring_example()
        elif choice == '3':
            cve_id = input("Enter a CVE ID to check for exploits: ")
            exploitability_checks(cve_id)
        elif choice == '0':
            break
        else:
            print("Invalid choice. Please try again.")

def html_report_generation(scan_results):
    print("Generating HTML Report...")
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"vulnerability_scan_report_{timestamp}.html"
    
    html_content = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Vulnerability Scan Report</title>
        <style>
            body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; margin: 0; padding: 20px; }}
            .container {{ max-width: 800px; margin: auto; }}
            h1, h2 {{ color: #2c3e50; }}
            table {{ width: 100%; border-collapse: collapse; margin-bottom: 20px; }}
            th, td {{ border: 1px solid #ddd; padding: 12px; text-align: left; }}
            th {{ background-color: #f2f2f2; }}
            .severity-critical {{ background-color: #ff4444; color: white; }}
            .severity-high {{ background-color: #ffbb33; }}
            .severity-medium {{ background-color: #ffeb3b; }}
            .severity-low {{ background-color: #00C851; }}
        </style>
    </head>
    <body>
        <div class="container">
            <h1>Vulnerability Scan Report</h1>
            <p>Scan performed on: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
            
            <h2>Scan Results</h2>
            <table>
                <tr>
                    <th>Target</th>
                    <th>Vulnerability</th>
                    <th>Severity</th>
                    <th>Description</th>
                </tr>
    """
    
    for target, vulnerabilities in scan_results.items():
        for vuln in vulnerabilities:
            severity_class = f"severity-{vuln['severity'].lower()}"
            html_content += f"""
                <tr>
                    <td>{target}</td>
                    <td>{vuln['name']}</td>
                    <td class="{severity_class}">{vuln['severity']}</td>
                    <td>{vuln['description']}</td>
                </tr>
            """
    
    html_content += """
            </table>
        </div>
    </body>
    </html>
    """
    
    with open(filename, 'w') as f:
        f.write(html_content)
    
    print(f"HTML report generated: {filename}")
    print(f"Report saved in: {os.path.abspath(filename)}")
    # Sample scan results
    sample_results = {
        "192.168.1.1": [
            {"name": "CVE-2021-1234", "severity": "High", "description": "Buffer overflow vulnerability in service X"},
            {"name": "CVE-2021-5678", "severity": "Medium", "description": "Cross-site scripting vulnerability in application Y"}
        ],
        "10.0.0.1": [
            {"name": "CVE-2021-9101", "severity": "Critical", "description": "Remote code execution vulnerability in service Z"}
        ]
    }
    
    html_report_generation(sample_results)


def json_output(scan_results):
    print("Generating JSON Output...")
    
    # Add metadata to the scan results
    output_data = {
        "scan_timestamp": datetime.now().isoformat(),
        "scanner_version": "1.0",  # You should update this with your actual version number
        "results": scan_results
    }
    
    try:
        # Convert the data to JSON format
        json_data = json.dumps(output_data, indent=4)
        
        # Generate a filename with timestamp
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"vulnerability_scan_results_{timestamp}.json"
        
        # Save the JSON data to a file
        with open(filename, 'w') as f:
            f.write(json_data)
        
        print(f"JSON output generated and saved to: {os.path.abspath(filename)}")
        
        # Ask if the user wants to display the JSON in the console
        display_option = input("Do you want to display the JSON output in the console? (y/n): ")
        if display_option.lower() == 'y':
            print("\nJSON Output:")
            print(json_data)
    
    except json.JSONEncodeError as e:
        print(f"Error encoding JSON: {e}")
    except IOError as e:
        print(f"Error writing to file: {e}")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")

    sample_results = {
        "192.168.1.1": [
            {
                "name": "CVE-2021-1234",
                "severity": "High",
                "description": "Buffer overflow vulnerability in service X",
                "cvss_score": 8.5
            },
            {
                "name": "CVE-2021-5678",
                "severity": "Medium",
                "description": "Cross-site scripting vulnerability in application Y",
                "cvss_score": 6.5
            }
        ],
        "10.0.0.1": [
            {
                "name": "CVE-2021-9101",
                "severity": "Critical",
                "description": "Remote code execution vulnerability in service Z",
                "cvss_score": 9.8
            }
        ]
    }
    
    json_output(sample_results)


def verbose_mode():
    global VERBOSE_MODE
    print("\nVerbose Mode Settings")
    print("---------------------")
    print(f"Current status: {'Enabled' if VERBOSE_MODE else 'Disabled'}")
    
    choice = input("Do you want to enable verbose mode? (y/n): ").lower()
    if choice == 'y':
        VERBOSE_MODE = True
        print("Verbose mode enabled.")
    elif choice == 'n':
        VERBOSE_MODE = False
        print("Verbose mode disabled.")
    else:
        print("Invalid choice. Verbose mode status unchanged.")

def verbose_print(message):
    if VERBOSE_MODE:
        print(f"[VERBOSE] {message}")

# Example of how to modify an existing function to use verbose mode
def tcp_port_scan(target, start_port, end_port):
    try:
        ip = socket.gethostbyname(target)
        verbose_print(f"Resolved {target} to IP: {ip}")
        
        print(f"\nScanning {target} ({ip}) for open TCP ports...")
        
        open_ports = []
        for port in range(start_port, end_port + 1):
            verbose_print(f"Scanning port {port}")
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((ip, port))
            if result == 0:
                open_ports.append(port)
                print(f"Port {port}: Open")
            sock.close()
        
        if not open_ports:
            print("No open ports found.")
        
        verbose_print(f"Scan completed. Found {len(open_ports)} open port(s).")
    
    except socket.gaierror:
        print("Hostname could not be resolved.")
    except socket.error:
        print("Couldn't connect to server.")

# Example usage in the main menu
def tcp_scan_menu():
    while True:
        print("\nTCP Scan Menu")
        print("1. Run TCP Port Scan")
        print("2. Toggle Verbose Mode")
        print("3. Exit")
        
        choice = input("Enter your choice: ")
        
        if choice == '1':
            target = input("Enter target IP or hostname: ")
            start_port = int(input("Enter start port: "))
            end_port = int(input("Enter end port: "))
            tcp_port_scan(target, start_port, end_port)
        elif choice == '2':
            verbose_mode()
        elif choice == '3':
            print("Exiting...")
            break
        else:
            print("Invalid choice. Please try again.")

def progress_bar(iteration, total, prefix='', suffix='', decimals=1, length=50, fill='█', print_end="\r"):
    """
    Call in a loop to create terminal progress bar
    @params:
        iteration   - Required  : current iteration (Int)
        total       - Required  : total iterations (Int)
        prefix      - Optional  : prefix string (Str)
        suffix      - Optional  : suffix string (Str)
        decimals    - Optional  : positive number of decimals in percent complete (Int)
        length      - Optional  : character length of bar (Int)
        fill        - Optional  : bar fill character (Str)
        print_end   - Optional  : end character (e.g. "\r", "\r\n") (Str)
    """
    percent = ("{0:." + str(decimals) + "f}").format(100 * (iteration / float(total)))
    filled_length = int(length * iteration // total)
    bar = fill * filled_length + '-' * (length - filled_length)
    print(f'\r{prefix} |{bar}| {percent}% {suffix}', end=print_end)
    # Print New Line on Complete
    if iteration == total: 
        print()

def example_long_running_task():
    """Example function to demonstrate the use of the progress bar"""
    total_operations = 100
    print("Starting a long-running task...")
    for i in range(total_operations):
        # Simulate some work
        time.sleep(0.1)
        # Update the progress bar
        progress_bar(i + 1, total_operations, prefix='Progress:', suffix='Complete', length=50)

# Example usage in a scanning function
def port_scan_with_progress(target, start_port, end_port):
    try:
        ip = socket.gethostbyname(target)
        print(f"\nScanning {target} ({ip}) for open ports...")
        
        open_ports = []
        total_ports = end_port - start_port + 1
        
        for i, port in enumerate(range(start_port, end_port + 1), 1):
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((ip, port))
            if result == 0:
                open_ports.append(port)
            sock.close()
            
            # Update progress bar
            progress_bar(i, total_ports, prefix='Scan Progress:', suffix='Complete', length=50)
        
        print("\nScan completed.")
        if open_ports:
            print("Open ports:")
            for port in open_ports:
                print(f"Port {port}: Open")
        else:
            print("No open ports found.")
    
    except socket.gaierror:
        print("Hostname could not be resolved.")
    except socket.error:
        print("Couldn't connect to server.")

# Example usage in the main menu
def port_scan_menu():
    while True:
        print("\nMain Menu")
        print("1. Run Port Scan with Progress Bar")
        print("2. Run Example Long Task")
        print("3. Exit")
        
        choice = input("Enter your choice: ")
        
        if choice == '1':
            target = input("Enter target IP or hostname: ")
            start_port = int(input("Enter start port: "))
            end_port = int(input("Enter end port: "))
            port_scan_with_progress(target, start_port, end_port)
        elif choice == '2':
            example_long_running_task()
        elif choice == '3':
            print("Exiting...")
            break
        else:
            print("Invalid choice. Please try again.")

# User Experience functions
def cli_improvements():
    parser = argparse.ArgumentParser(
        description="NebulaScan - Advanced Network Vulnerability Scanner",
        epilog="Use 'nebulascan <command> -h' for more information on a specific command."
    )

    # Add main commands
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # Scan command
    scan_parser = subparsers.add_parser("scan", help="Perform a vulnerability scan")
    scan_parser.add_argument("-t", "--target", required=True, help="Target IP address or hostname")
    scan_parser.add_argument("-p", "--ports", default="1-1000", help="Port range to scan (e.g., '1-1000' or '80,443,8080')")
    scan_parser.add_argument("--tcp", action="store_true", help="Perform TCP scan")
    scan_parser.add_argument("--udp", action="store_true", help="Perform UDP scan")
    scan_parser.add_argument("--syn", action="store_true", help="Perform SYN scan (requires root privileges)")

    # Report command
    report_parser = subparsers.add_parser("report", help="Generate a report")
    report_parser.add_argument("-f", "--format", choices=["html", "json"], default="html", help="Report format")
    report_parser.add_argument("-o", "--output", help="Output file name")

    # Update command
    update_parser = subparsers.add_parser("update", help="Update vulnerability database")

    # Verbose mode
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")

    # Parse arguments
    args = parser.parse_args()

    # Process the arguments
    if args.command == "scan":
        print(f"Performing {'TCP' if args.tcp else 'UDP' if args.udp else 'SYN' if args.syn else 'TCP'} scan on {args.target}")
        print(f"Port range: {args.ports}")
        # Here you would call your scanning function with the provided arguments
        # For example: perform_scan(args.target, args.ports, scan_type='tcp' if args.tcp else 'udp' if args.udp else 'syn')
    elif args.command == "report":
        print(f"Generating {args.format.upper()} report")
        if args.output:
            print(f"Saving report to {args.output}")
        # Here you would call your report generation function
        # For example: generate_report(format=args.format, output_file=args.output)
    elif args.command == "update":
        print("Updating vulnerability database")
        # Here you would call your database update function
        # For example: update_vulnerability_database()
    else:
        parser.print_help()

    # Handle verbose mode
    if args.verbose:
        print("Verbose mode enabled")
        # Here you would set your global VERBOSE_MODE flag
        # For example: set_verbose_mode(True)

def configuration_file():
    global CVE_DB_PATH, SCAN_DELAY, USE_RANDOMIZED_PORTS

    print("\nConfiguration File Management")
    print("-----------------------------")
    print("1. View current configuration")
    print("2. Edit configuration")
    print("3. Save configuration")
    print("0. Back to main menu")

    choice = input("Enter your choice: ")

    if choice == '1':
        print(f"CVE_DB_PATH: {CVE_DB_PATH}")
        print(f"SCAN_DELAY: {SCAN_DELAY}")
        print(f"USE_RANDOMIZED_PORTS: {USE_RANDOMIZED_PORTS}")
    elif choice == '2':
        CVE_DB_PATH = input(f"Enter new CVE_DB_PATH (current: {CVE_DB_PATH}): ") or CVE_DB_PATH
        SCAN_DELAY = float(input(f"Enter new SCAN_DELAY (current: {SCAN_DELAY}): ") or SCAN_DELAY)
        USE_RANDOMIZED_PORTS = input(f"Use randomized ports? (y/n, current: {USE_RANDOMIZED_PORTS}): ").lower() == 'y'
    elif choice == '3':
        save_config()
        print("Configuration saved.")
    elif choice == '0':
        return
    else:
        print("Invalid choice.")

    configuration_file()  # Recursive call to stay in the configuration menu
def target_list_import():
    logging.info("Importing Target List...")
    file_path = input("Enter the path to the target list file (CSV format): ")
    targets = []
    try:
        with open(file_path, 'r') as file:
            csv_reader = csv.reader(file)
            for row in csv_reader:
                targets.extend(row)
        print(f"Successfully imported {len(targets)} targets.")
        return targets
    except FileNotFoundError:
        print("File not found. Please check the file path and try again.")
    except Exception as e:
        print(f"An error occurred while importing targets: {e}")
    return []

def web_application_scanning():
    logging.info("Scanning Web Application...")
    target_url = input("Enter the target URL to scan: ")
    print(f"Scanning web application at {target_url}")
    # This is a basic implementation. In a real scenario, you'd use a library like 'requests' to check for common vulnerabilities
    try:
        response = requests.get(target_url)
        print(f"Status Code: {response.status_code}")
        print(f"Server: {response.headers.get('Server', 'Unknown')}")
        # Check for basic security headers
        security_headers = ['X-XSS-Protection', 'X-Frame-Options', 'Content-Security-Policy']
        for header in security_headers:
            if header in response.headers:
                print(f"{header} is set: {response.headers[header]}")
            else:
                print(f"{header} is not set")
    except requests.exceptions.RequestException as e:
        print(f"An error occurred during the web application scan: {e}")

def network_mapping():
    logging.info("Mapping Network...")
    target_ip = input("Enter the target IP range (e.g., 192.168.1.0/24): ")
    print(f"Mapping network: {target_ip}")
    try:
        arp = ARP(pdst=target_ip)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether/arp
        result = srp(packet, timeout=3, verbose=0)[0]
        devices = []
        for sent, received in result:
            devices.append({'ip': received.psrc, 'mac': received.hwsrc})
        print("Network Devices:")
        print("IP" + " "*18 + "MAC")
        print("-"*33)
        for device in devices:
            print(f"{device['ip']:16}    {device['mac']}")
    except Exception as e:
        print(f"An error occurred during network mapping: {e}")

def firewall_ids_evasion():
    logging.info("Applying Firewall/IDS Evasion Techniques...")
    print("Firewall/IDS Evasion Techniques:")
    print("1. IP Fragmentation")
    print("2. TCP Segmentation")
    print("3. Source Port Manipulation")
    choice = input("Select an evasion technique (1-3): ")
    # This is a placeholder. Actual implementation would involve packet manipulation.
    print(f"Evasion technique {choice} applied. (Note: This is a simulated action)")

def script_execution():
    logging.info("Executing Custom Script...")
    script_path = input("Enter the path to your custom Python script: ")
    try:
        result = subprocess.run(["python", script_path], capture_output=True, text=True)
        print("Script Output:")
        print(result.stdout)
        if result.stderr:
            print("Errors:")
            print(result.stderr)
    except Exception as e:
        print(f"An error occurred while executing the script: {e}")

def multithreading():
    logging.info("Configuring Multithreading...")
    global MAX_THREADS
    thread_count = input("Enter the number of threads to use (default is 100): ") or "100"
    try:
        MAX_THREADS = int(thread_count)
        print(f"Multithreading configured with {MAX_THREADS} threads.")
    except ValueError:
        print("Invalid input. Using default value of 100 threads.")
        MAX_THREADS = 100

def proxy_support():
    logging.info("Configuring Proxy Support...")
    proxy_url = input("Enter proxy URL (e.g., http://proxy.example.com:8080): ")
    if proxy_url:
        proxies = {
            "http": proxy_url,
            "https": proxy_url
        }
        try:
            response = requests.get("http://example.com", proxies=proxies, timeout=5)
            print(f"Proxy configured successfully. Status code: {response.status_code}")
            return proxies
        except requests.exceptions.RequestException as e:
            print(f"Failed to configure proxy: {e}")
    else:
        print("No proxy configured.")
    return None

def cloud_integration():
    logging.info("Integrating with Cloud Services...")
    print("Cloud Integration Options:")
    print("1. AWS")
    print("2. Azure")
    print("3. Google Cloud")
    choice = input("Select a cloud provider (1-3): ")
    # This is a placeholder. Actual implementation would involve cloud-specific SDKs.
    print(f"Cloud integration for option {choice} is simulated. (Note: Actual integration needs to be implemented)")

def api_integration():
    logging.info("Setting up API Integration...")
    api_key = input("Enter your API key: ")
    api_url = input("Enter the API URL: ")
    # This is a placeholder. Actual implementation would involve making API calls.
    print(f"API integration set up for {api_url}")
    print(f"API Key: {'*' * len(api_key)}")  # Don't print the actual API key

def scheduled_scans():
    logging.info("Scheduling Scans...")
    frequency = input("Enter scan frequency (daily/weekly/monthly): ")
    time = input("Enter scan time (HH:MM): ")
    try:
        schedule_time = datetime.strptime(time, "%H:%M")
        next_run = datetime.now().replace(hour=schedule_time.hour, minute=schedule_time.minute, second=0, microsecond=0)
        if next_run <= datetime.now():
            if frequency == 'daily':
                next_run += timedelta(days=1)
            elif frequency == 'weekly':
                next_run += timedelta(weeks=1)
            elif frequency == 'monthly':
                next_run += timedelta(days=30)  # Approximate
        print(f"Next scan scheduled for: {next_run}")
    except ValueError:
        print("Invalid time format. Please use HH:MM.")

def load_config():
    global CVE_DB_PATH, SCAN_DELAY, USE_RANDOMIZED_PORTS
    try:
        with open('config.json', 'r') as config_file:
            config = json.load(config_file)
            CVE_DB_PATH = config.get('CVE_DB_PATH', CVE_DB_PATH)
            SCAN_DELAY = config.get('SCAN_DELAY', SCAN_DELAY)
            USE_RANDOMIZED_PORTS = config.get('USE_RANDOMIZED_PORTS', USE_RANDOMIZED_PORTS)
            print("Configuration loaded successfully.")
    except FileNotFoundError:
        print("Configuration file not found. Using default settings.")
    except json.JSONDecodeError:
        print("Error decoding configuration file. Using default settings.")

def main():
    load_config()  # Load configuration at startup
    
    parser = argparse.ArgumentParser(description="NebulaScan - Advanced Network Vulnerability Scanner")
    parser.add_argument("-c", "--cli", action="store_true", help="Run in CLI mode")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")
    args = parser.parse_args()

    global VERBOSE_MODE
    VERBOSE_MODE = args.verbose

    setup_logging()  # Set up logging after parsing arguments

    if args.verbose:
        logging.getLogger().setLevel(logging.INFO)
    
    if args.cli:
        cli_improvements()
    else:
        main_menu()

if __name__ == "__main__":
    main()
