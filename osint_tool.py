import argparse
import requests
import logging
import json
import os
from datetime import datetime

# Set up logging
def setup_logger():
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(levelname)s - %(message)s"
    )

# Function to ensure output directory exists
def ensure_output_dir(directory):
    try:
        if not os.path.exists(directory):
            os.makedirs(directory)
            logging.info(f"Created output directory: {directory}")
    except Exception as e:
        logging.error(f"Error creating directory {directory}: {e}")

# Fetch IP info from IPinfo.io
def get_ip_info(ip):
    try:
        url = f"https://ipinfo.io/{ip}/json"
        response = requests.get(url)

        if response.status_code == 200:
            return response.json()
        else:
            logging.error(f"Failed to fetch IP info for {ip}. Status: {response.status_code}")
            return None
    except requests.exceptions.RequestException as e:
        logging.error(f"Error fetching IP info: {e}")
        return None

# (Removed) Fetch domain info using Shodan

# Save raw JSON data to a file
def save_json_data(data, filename):
    try:
        with open(filename, 'w') as f:
            json.dump(data, f, indent=4)
        print(f"JSON data saved to {filename}")
    except Exception as e:
        logging.error(f"Error saving JSON data to {filename}: {e}")

# Save report to a file
def save_report(report, filename):
    try:
        with open(filename, 'w') as f:
            f.write(report)
        print(f"Report saved to {filename}")
    except Exception as e:
        logging.error(f"Error saving report to {filename}: {e}")

# Generate human-readable report
def generate_report(ip_info):
    report = "OSINT Tool Report\n"
    report += "=" * 40 + "\n"

    if ip_info:
        report += "IP Information:\n"
        report += f"IP: {ip_info.get('ip')}\n"
        report += f"Location: {ip_info.get('city')}, {ip_info.get('region')}, {ip_info.get('country')}\n"
        report += f"Org: {ip_info.get('org')}\n"
    else:
        report += "IP Information: Not found\n"

    return report

# Function to get the timestamp for filenames
def get_timestamp():
    return datetime.now().strftime("%Y-%m-%d_%H-%M-%S")

# Main function
def main():
    setup_logger()

    # Parse command-line arguments
    parser = argparse.ArgumentParser(description="OSINT Tool for IP Information")
    parser.add_argument("target", help="Target IP address or domain to gather information about.", nargs="?", default=None)
    parser.add_argument("--output", help="Output file to save the report.", default=None)
    parser.add_argument("--json-output", help="Output file to save raw JSON data.", default=None)
    args = parser.parse_args()

    # Ensure output directory exists
    ensure_output_dir("output")

    # If no arguments are provided, prompt the user for input
    if not args.target:
        args.target = input("Enter the target (IP address or domain): ")

    # Validate input
    if not args.target:
        print("Error: Target is required.")
        return

    # Determine target type
    is_ip = args.target.replace('.', '').isdigit()
    ip_info = get_ip_info(args.target) if is_ip else None
    # Removed: domain_info = get_domain_info(args.target, args.shodan_api_key) if not is_ip else None

    if not ip_info:
        print("No valid information found.")
        return

    # Generate output filenames with a timestamp
    timestamp = get_timestamp()
    output_filename = args.output if args.output else f"output/report_{timestamp}.txt"
    json_output_filename = args.json_output if args.json_output else f"output/raw_data_{timestamp}.json"

    # Generate and save reports
    report = generate_report(ip_info)
    save_report(report, output_filename)

    # Save JSON data
    save_json_data({"ip_info": ip_info}, json_output_filename)
    print("OSINT scan completed.")

if __name__ == "__main__":
    main()
