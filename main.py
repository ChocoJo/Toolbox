import argparse
from osint_tool import main as osint_main
from subdomain_enum import main as subdomain_enum_main
from hash_cracker import main as hash_cracker_main
from port_scanner import main as port_scanner_main
import logging

# Setup logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

TOOLS = {
    "osint": osint_main,
    "subdomain enumeration": subdomain_enum_main,
    "hash cracker": hash_cracker_main,
    "port scanner": port_scanner_main
}

def display_menu():
    """Displays the main menu for the application."""
    print("\nWelcome to the Multi-Tool Application!")
    print("Select a tool to use:")
    for index, tool in enumerate(TOOLS, start=1):
        print(f"{index}. {tool.capitalize()} Tool")
    print(f"{len(TOOLS)+1}. Exit")

def interactive_mode():
    """Interactive mode for the main script."""
    while True:
        display_menu()
        choice = input("Enter your choice: ").strip()

        if choice.isdigit() and 1 <= int(choice) <= len(TOOLS):
            tool_name = list(TOOLS.keys())[int(choice) - 1]
            logging.info(f"Launching {tool_name.capitalize()} Tool.")
            TOOLS[tool_name]()
        elif choice == str(len(TOOLS)+1):
            print("\nExiting the application. Goodbye!")
            break
        else:
            print("Invalid choice. Please try again.\n")

def main():
    parser = argparse.ArgumentParser(description="Multi-Tool Application")
    parser.add_argument("--tool", choices=TOOLS.keys(), help="The tool to run directly")
    parser.add_argument("args", nargs=argparse.REMAINDER, help="Arguments for the selected tool")
    args = parser.parse_args()

    if args.tool:
        # Run the specified tool directly
        logging.info(f"Running {args.tool.capitalize()} Tool with arguments: {args.args}")
        try:
            TOOLS[args.tool](*args.args)
        except Exception as e:
            logging.error(f"Error running {args.tool} tool: {e}")
    else:
        interactive_mode()

if __name__ == "__main__":
    main()
