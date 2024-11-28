import requests
import re
import logging
import argparse
import os
 
# Setup logging
def setup_logger():
    """Setup logging configuration."""
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(levelname)s - %(message)s"
    )
 
# Validate if the host is a valid domain
def is_valid_host(host):
    """Validates if the host is a valid domain."""
    domain_regex = re.compile(r'^(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+(?:[A-Za-z]{2,6}|[A-Za-z0-9-]{2,})$')
    return bool(re.match(domain_regex, host))
 
# Function to handle user input for the host (domain)
def get_host_input():
    host = input("Enter the host (domain) to enumerate subdomains: ").strip()
    if not is_valid_host(host):
        print("Invalid domain. Please enter a valid domain.")
        return get_host_input()
    return host
 
# Function to check if the subdomain exists
def check_subdomain(host, subdomain):
    """Check if a subdomain is valid by sending an HTTP request."""
    url = f"http://{subdomain}.{host}"
    try:
        response = requests.get(url, timeout=5)
        if response.status_code == 200:
            logging.info(f"Valid subdomain: {subdomain}.{host}")
            return True
    except requests.exceptions.RequestException as e:
        logging.debug(f"Error checking {subdomain}.{host}: {e}")
    return False
 
# Function to perform subdomain enumeration
def enumerate_subdomains(host, subdomains_list):
    """Enumerates subdomains for a given host."""
    valid_subdomains = []
    for subdomain in subdomains_list:
        if check_subdomain(host, subdomain):
            valid_subdomains.append(subdomain)
    return valid_subdomains
 
# Function to generate a report for valid subdomains
def generate_report(host, valid_subdomains):
    """Generate a simple report for the found subdomains."""
    report = f"Subdomain Enumeration Report for {host}\n"
    report += "=" * 40 + "\n"
    report += "Valid Subdomains:\n"
    if valid_subdomains:
        for subdomain in valid_subdomains:
            report += f"- {subdomain}.{host}\n"
    else:
        report += "No valid subdomains found.\n"
    return report
 
# Function to save the report to a file
def save_report(report, filename):
    """Save the generated report to a file."""
    try:
        with open(filename, 'w') as f:
            f.write(report)
        print(f"Report saved to {filename}")
    except Exception as e:
        logging.error(f"Error saving report to {filename}: {e}")
 
# Function to read subdomains from a file
def read_subdomains_file(file_path):
    """Read subdomains from the given file."""
    if os.path.exists(file_path):
        try:
            with open(file_path, "r") as file:
                return [line.strip() for line in file.readlines()]
        except Exception as e:
            logging.error(f"Error reading subdomains file: {e}")
            return None
    else:
        print(f"Subdomains file '{file_path}' not found.")
        return None
 
# Function to prompt user for a subdomains file if the default file is missing
def prompt_for_subdomains_file():
    """Prompt user for a valid subdomains file if the default file is missing."""
    file_path = input("Please enter the path to a subdomains file: ").strip()
    while not os.path.exists(file_path):
        print(f"The file '{file_path}' was not found.")
        file_path = input("Please enter a valid path to a subdomains file: ").strip()
    return file_path
 
# Main function for the subdomain enumeration tool
def main():
    # Setup logging
    setup_logger()
 
    # Parse command-line arguments
    parser = argparse.ArgumentParser(description="Subdomain Enumeration Tool")
    parser.add_argument("host", nargs="?", help="Host (domain) to enumerate subdomains for.")
    parser.add_argument("--subdomains-file", default="common.txt", help="File containing list of subdomains to test.")
    parser.add_argument("--output", help="Output file to save the report.")
    args = parser.parse_args()
 
    # Get the host input (either from arguments or prompt)
    host = args.host if args.host else get_host_input()
 
    # Check if the subdomains file exists or prompt the user
    subdomains_list = read_subdomains_file(args.subdomains_file)
    if subdomains_list is None:
        # If the default file isn't found, prompt the user for a file
        subdomains_file = prompt_for_subdomains_file()
        subdomains_list = read_subdomains_file(subdomains_file)
 
    # Enumerate subdomains for the host
    print(f"Enumerating subdomains for {host}...")
    valid_subdomains = enumerate_subdomains(host, subdomains_list)
 
    # Generate the report
    report = generate_report(host, valid_subdomains)
    print(report)
 
    # Save the report if specified
    if args.output:
        save_report(report, args.output)
 
if __name__ == "__main__":
    main()