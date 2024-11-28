import socket
import argparse
import logging
import re
import sys
import subprocess
import os
from scapy.all import sr1, IP, TCP
 
# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def is_valid_host(host):
    """Validate if the host is a valid IP (IPv4 or IPv6) or domain."""
    # Check for valid IPv4
    try:
        socket.inet_pton(socket.AF_INET, host)
        return True
    except socket.error:
        logging.debug(f"Invalid IPv4 address: {host}")

    # Check for valid IPv6
    try:
        socket.inet_pton(socket.AF_INET6, host)
        return True
    except socket.error:
        logging.debug(f"Invalid IPv6 address: {host}")

    # Check if it's a valid domain using regex
    domain_regex = re.compile(
        r'^(?:[a-zA-Z0-9]'
        r'(?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+'
        r'(?:[a-zA-Z]{2,6}|[a-zA-Z0-9-]{2,})$'
    )
    if domain_regex.match(host):
        return True

    return False
 
def is_valid_port(port):
    """Checks if a given port is a valid integer between 1 and 65535."""
    try:
        port = int(port)
        if 1 <= port <= 65535:
            return True
    except ValueError:
        logging.debug(f"Invalid port input: {port}")
    return False
 
def get_valid_host(host=None):
    """Prompt user to input a valid host (IP address or domain), or use passed host."""
    if host is None:
        while True:
            host = input("Enter the host (IP or domain) to scan: ").strip()
            if is_valid_host(host):
                return host
            else:
                print("Invalid host. Please enter a valid IP address or domain.")
    elif is_valid_host(host):
        return host
    else:
        print("Invalid host provided via argument.")
        sys.exit(1)
 
def get_valid_ports(ports_input=None):
    """Prompt user to input valid ports or accept port arguments."""
    while True:
        if ports_input is None:
            ports_input = input("Enter the ports to scan (single port, comma separated ports or range 'start-end'): ").strip()
 
        ports = ports_input.split(',')
        valid_ports = set()
        invalid_ports = []
 
        for port in ports:
            port = port.strip()
            if '-' in port:  # Check if it's a range
                try:
                    start, end = map(int, port.split('-'))
                    if is_valid_port(start) and is_valid_port(end) and start <= end:
                        valid_ports.update(range(start, end + 1))
                    else:
                        invalid_ports.append(port)
                except ValueError:
                    invalid_ports.append(port)
            elif is_valid_port(port):
                valid_ports.add(int(port))
            else:
                invalid_ports.append(port)
 
        if invalid_ports:
            print(f"Invalid ports: {', '.join(invalid_ports)}. Please enter valid ports (1-65535).")
            ports_input = None
        else:
            return sorted(valid_ports)
 
def scan_port(host, port):
    """Performs a TCP connect scan on a specific port."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1)
            result = s.connect_ex((host, port))
            return result == 0
    except socket.timeout:
        logging.error(f"Timeout while scanning port {port} on {host}.")
        return False
    except socket.gaierror:
        logging.error(f"Host {host} could not be resolved.")
        return False
    except Exception as e:
        logging.error(f"Error scanning port {port} on {host}: {e}")
        return False
 
def syn_scan(host, port):
    """Performs a SYN scan on a specific port (stealth scan) using Scapy."""
    try:
        if os.geteuid() != 0:  # Check if script is run as root
            raise PermissionError("SYN scan requires root privileges.")
        
        # Create an IP/TCP packet with SYN flag set
        ip = IP(dst=host)
        syn = TCP(dport=port, flags="S", seq=1000)
        response = sr1(ip/syn, timeout=1, verbose=False)
 
        if response and response.haslayer(TCP) and response.getlayer(TCP).flags == 0x12:  # SYN-ACK
            return True
        return False
    except PermissionError as e:
        logging.error(f"Permission error: {e}")
        return False
    except Exception as e:
        logging.error(f"SYN scan failed on port {port} for {host}: {e}")
        return False
 
def ping_scan(host):
    """Performs a simple ping to check if the host is alive."""
    try:
        # Use subprocess to send a ping request
        result = subprocess.run(['ping', '-c', '1', host], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if result.returncode == 0:
            logging.info(f"Host {host} is reachable.")
            return True
        else:
            logging.warning(f"Host {host} is not reachable.")
            return False
    except PermissionError:
        logging.error("Permission denied while attempting to ping the host.")
        return False
    except Exception as e:
        logging.error(f"Error pinging host {host}: {e}")
        return False
 
def version_detection(host, port):
    """Detects the version of a service running on the open port."""
    try:
        # Attempt to connect and get version info for a service
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1)
            s.connect((host, port))
            s.send(b'GET / HTTP/1.1\r\n\r\n')  # Basic HTTP request to fetch version
            response = s.recv(1024)
            if b'HTTP' in response:
                version_info = response.split(b'\r\n')[0].decode('utf-8')
                logging.info(f"Service version on port {port}: {version_info}")
                return version_info
            return "No version info found"
    except socket.timeout:
        logging.error(f"Timeout while detecting version for port {port} on {host}.")
        return None
    except socket.error as e:
        logging.error(f"Socket error during version detection for port {port} on {host}: {e}")
        return None
    except Exception as e:
        logging.error(f"Version detection failed for port {port} on {host}: {e}")
        return None
 
def port_scanner(host, ports, scan_type):
    """Performs port scanning based on the selected scan type."""
    open_ports = []
    closed_ports = []
 
    for port in ports:
        try:
            if scan_type == "tcp":
                if scan_port(host, port):
                    open_ports.append(port)
                else:
                    closed_ports.append(port)
            elif scan_type == "syn":
                if syn_scan(host, port):
                    open_ports.append(port)
                else:
                    closed_ports.append(port)
            elif scan_type == "ping":
                if ping_scan(host):
                    open_ports.append(port)  # Just marking the host as alive
            elif scan_type == "version":
                version_info = version_detection(host, port)
                if version_info:
                    open_ports.append((port, version_info))
                else:
                    closed_ports.append(port)
        except Exception as e:
            logging.error(f"Error scanning port {port} on {host}: {e}")
 
    return open_ports, closed_ports
 
def get_scan_type_from_user():
    """Prompt user to select scan type interactively."""
    print("\nChoose the scan type:")
    print("1. TCP Scan (-sT)")
    print("2. SYN Scan (-sS)")
    print("3. Ping Scan (-sn)")
    print("4. Version Detection (-sV)")
    choice = input("Enter the number corresponding to the scan type: ").strip()
 
    if choice == "1":
        return "tcp"
    elif choice == "2":
        return "syn"
    elif choice == "3":
        return "ping"
    elif choice == "4":
        return "version"
    else:
        print("Invalid choice, defaulting to TCP scan.")
        return "tcp"
 
def generate_report(host, open_ports, closed_ports):
    """Generates a simple report of the scan."""
    report = f"Scan Report for {host}\n"
    report += "=" * 40 + "\n"
    report += f"Open ports: {open_ports}\n"
    report += f"Closed ports: {closed_ports}\n"
    return report
 
def main():
    parser = argparse.ArgumentParser(description="Port Scanner Tool")
    parser.add_argument("host", nargs="?", default=None, help="Host to scan (IP or domain)")
    parser.add_argument("ports", nargs="?", default=None, help="Ports to scan (comma separated or range 'start-end')")
    parser.add_argument("--scan-type", choices=["tcp", "syn", "ping", "version"], default=None, help="Type of scan to perform")
    args = parser.parse_args()
 
    host = get_valid_host(args.host)
    ports = get_valid_ports(args.ports)
 
    # If the user hasn't specified a scan type, ask them to choose one interactively
    scan_type = args.scan_type or get_scan_type_from_user()
 
    try:
        open_ports, closed_ports = port_scanner(host, ports, scan_type)
        logging.info(f"Open ports on {host}: {open_ports}")
        logging.info(f"Closed ports on {host}: {closed_ports}")
        print(f"Open ports on {host}: {open_ports}")
        print(f"Closed ports on {host}: {closed_ports}")
 
        # Generate a report
        report = generate_report(host, open_ports, closed_ports)
        logging.info("Generated scan report.")
        print(report)
 
    except Exception as e:
        logging.error(f"An error occurred: {e}")
        print(f"An error occurred: {e}")
 
if __name__ == "__main__":
    main()