import socket
import concurrent.futures
import ipaddress
import struct
import os
import sys
import random
import datetime
import time
import gzip
import json
import requests
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
from scapy.all import sr1, IP, TCP
# Global variable for database path
CVE_DB_PATH = 'cve_database.db'

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
            tcp_port_scan()
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
        print(f"\nScanning {target} ({ip}) for open TCP ports...")
        
        # Validate IP address
        ipaddress.ip_address(ip)
        
        # Validate port range
        if not 1 <= start_port <= end_port <= 65535:
            raise ValueError("Invalid port range")
        
        open_ports = scan_ports(ip, start_port, end_port)
        
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
def cve_database_integration():
    print("Integrating CVE Database...")
    # Implement CVE database integration logic here

def vulnerability_severity_scoring():
    print("Scoring Vulnerability Severity...")
    # Implement vulnerability severity scoring logic here

def exploitability_checks():
    print("Checking Exploitability...")
    # Implement exploitability checks logic here

# Reporting and Output functions
def html_report_generation():
    print("Generating HTML Report...")
    # Implement HTML report generation logic here

def json_output():
    print("Generating JSON Output...")
    # Implement JSON output logic here

def verbose_mode():
    print("Enabling Verbose Mode...")
    # Implement verbose mode logic here

def progress_bar():
    print("Showing Progress Bar...")
    # Implement progress bar logic here

# User Experience functions
def cli_improvements():
    print("Implementing CLI Improvements...")
    # Implement CLI improvements logic here

def configuration_file():
    print("Managing Configuration File...")
    # Implement configuration file management logic here

def target_list_import():
    print("Importing Target List...")
    # Implement target list import logic here

# Advanced Features functions
def web_application_scanning():
    print("Scanning Web Application...")
    # Implement web application scanning logic here

def network_mapping():
    print("Mapping Network...")
    # Implement network mapping logic here

def firewall_ids_evasion():
    print("Applying Firewall/IDS Evasion Techniques...")
    # Implement firewall/IDS evasion logic here

def script_execution():
    print("Executing Custom Script...")
    # Implement custom script execution logic here

def multithreading():
    print("Enabling Multithreading...")
    # Implement multithreading logic here

def proxy_support():
    print("Configuring Proxy Support...")
    # Implement proxy support logic here

def cloud_integration():
    print("Integrating with Cloud Services...")
    # Implement cloud integration logic here

def api_integration():
    print("Setting up API Integration...")
    # Implement API integration logic here

def scheduled_scans():
    print("Scheduling Scans...")
    # Implement scheduled scans logic here

if __name__ == "__main__":
    main_menu()
   update_cve_database()
    view_database_status()
    search_vulnerabilities("Apache")
