# Multi-Tool Application
 
## Overview
This project is a collection of Python-based tools designed for cybersecurity, information gathering, and utility tasks. The tools are packaged together with a main script that allows for both interactive and direct execution.
 
### Tools Included
1. **OSINT Tool**: Gathers information about IPs.
2. **Hash Cracker Tool**: Encrypts, decrypts, and hashes passwords securely.
3. **Port Scanner Tool**: Scans and identifies open ports on a target host.
4. **Subdomain Enumeration Tool**: Discovers valid subdomains for a domain.
 
The tools are accessible via a user-friendly interactive menu or directly through the command line.
 
---
 
## Tools Description and Usage
 
### **1. OSINT Tool**
- **Purpose**: Retrieve information about IP addresses.
- **Features**:
  - Fetch IP geolocation and ISP details using IPinfo.
- **Command-Line Usage**:
  ```bash
  python osint_tool.py <target> [--output <file>] [--json-output <file>]
  ```
  **Example**:
  ```bash
  python osint_tool.py 8.8.8.8 --output report.txt --json-output raw.json
  ```
- **Limitations**:
  - Only supports IP lookup.
  - Requires an active internet connection.
 
---
 
### **2. Hash Cracker Tool**
- **Purpose**: Securely encrypt, decrypt, and hash messages or passwords.
- **Features**:
  - AES encryption and decryption.
  - Password hashing with SHA256.
  - Key generation using PBKDF2.
- **Command-Line Usage**:
  ```bash
  python hash_cracker.py [options]
  ```
  **Options**:
  - Encrypt a message:
    ```bash
    python hash_cracker.py --encrypt "Hello World" --password "securepassword"
    ```
  - Decrypt a message:
    ```bash
    python hash_cracker.py --decrypt "<encrypted_hex>" --password "securepassword"
    ```
  - Hash a password:
    ```bash
    python hash_cracker.py --hash "password123"
    ```
  - Generate a key:
    ```bash
    python hash_cracker.py --generate-key --password "mypassword"
    ```
- **Limitations**:
  - AES decryption requires the same password used for encryption.
  - Encryption is limited to AES in CBC mode.
 
---
 
### **3. Port Scanner Tool**
- **Purpose**: Scan and identify open ports on a target.
- **Features**:
  - Perform TCP Connect Scan.
  - SYN Stealth Scan (requires root privileges).
  - Ping Scan to check host availability.
  - Service version detection for open ports.
- **Command-Line Usage**:
  ```bash
  python port_scanner.py <host> <ports> [--scan-type <type>]
  ```
  **Arguments**:
  - `<host>`: The target IP or domain.
  - `<ports>`: Ports to scan (e.g., `1-1000` or `22,80`).
  - `--scan-type`: The type of scan (`tcp`, `syn`, `ping`, `version`).
 
  **Example**:
  ```bash
  python port_scanner.py 192.168.1.1 1-100 --scan-type tcp
  ```
- **Limitations**:
  - SYN scan requires root privileges.
  - Version detection depends on the response from the service.
 
---
 
### **4. Subdomain Enumeration Tool**
- **Purpose**: Discover valid subdomains for a given domain.
- **Features**:
  - Validates subdomains from a user-provided list.
  - Generates and saves reports of discovered subdomains.
- **Command-Line Usage**:
  ```bash
  python subdomain_enum.py <host> [--subdomains-file <file>] [--output <file>]
  ```
  **Example**:
  ```bash
  python subdomain_enum.py example.com --subdomains-file subdomains.txt --output results.txt
  ```
- **Limitations**:
  - Only checks for HTTP-based subdomains.
  - The quality of the results depends on the provided subdomain list.
 
---
 
### **5. Main Script**
- **Purpose**: Interactive front-end to execute any of the tools.
- **Features**:
  - Interactive menu for selecting and running tools.
  - Supports direct invocation of tools with arguments.
- **Interactive Mode**:
  ```bash
  python main.py
  ```
  Select tools interactively via the menu.
- **Direct Invocation**:
  ```bash
  python main.py --tool <tool-name> [tool-arguments]
  ```
  **Tools Available**:
  - `osint`: OSINT Tool
  - `hash`: Hash Cracker Tool
  - `port`: Port Scanner Tool
  - `subdomain`: Subdomain Enumeration Tool
 
  **Example**:
  ```bash
  python main.py --tool port --host 192.168.1.1 --ports 1-100 --scan-type tcp
  ```
 
---
 
## Installation
 
### **1. Clone the Repository**
```bash
git clone https://github.com/your-repo/multi-tool.git
cd multi-tool
```
 
### **2. Install Dependencies**
```bash
pip install -r requirements.txt
```
 
---
 
## Requirements
- **Python Version**: Python 3.8 or higher.
- **Dependencies**:
  - `requests` (OSINT Tool, Subdomain Enumeration)
  - `cryptography` (Hash Cracker Tool)
  - `scapy` (Port Scanner Tool)
  - `argparse` (For CLI argument parsing)
  - `logging` (For structured logging)
 
---
 
## Known Limitations
1. **OSINT Tool**:
   - Only supports IP lookup.
   - Requires an active internet connection.
 
2. **Hash Cracker Tool**:
   - AES decryption works only with the exact password used for encryption.
 
3. **Port Scanner Tool**:
   - SYN scans need root privileges.
   - Version detection depends on service responses.
 
4. **Subdomain Enumeration Tool**:
   - Results depend on the provided subdomain list.
   - Checks only HTTP subdomains.
 
---
