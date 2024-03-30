import argparse
import signal
import socket
from ipaddress import ip_address
from pygments import highlight
from pygments.formatters.terminal256 import Terminal256Formatter
from pygments.lexers.web import JsonLexer
from termcolor import colored

from warnings import filterwarnings

filterwarnings("ignore")

#Import functions
from src.ack_scan import ack_scan
from src.os_detection import os_detection
from src.banner_grabbing import banner_grabbing
from src.enumerate import syn_scan, tcp_connect_scan
from src.http_header_evaluation import http_header_evaluation

def main():
    # Create object ArgumentParser to get arguments from command line
    parser = argparse.ArgumentParser(description="Network Scanning Tool")

    # Add argument for Targets IP address
    parser.add_argument("ip", metavar="IP", type=str, help="IP address to scan")

    # Add argument for scanning type
    parser.add_argument(
        "-sS",
        "--syn-scan",
        action="store_true",
        help="Perform a SYN scan on specified ports",
    )
    parser.add_argument(
        "-sT",
        "--tcp-scan",
        action="store_true",
        help="Perform a TCP connect scan on specified ports",
    )
    parser.add_argument(
        "-sA",
        "--ack-scan",
        action="store_true",
        help="Perform an ACK scan on specified ports",
    )
    parser.add_argument(
        "-b",
        "--banner-grabbing",
        action="store_true",
        help="Perform banner grabbing on specified port",
    )
    parser.add_argument(
        "-he",
        "--http-header",
        action="store_true",
        help="Perform evaluation of HTTP headers on specified port",
    )
    parser.add_argument(
        "-d",
        "--os-detection",
        action="store_true",
        help="Detect operating system of the target device",
    )

    # Add argument for ports to scan
    parser.add_argument(
        "-p",
        "--ports",
        metavar="PORTS",
        type=str,
        help="Comma-separated list of ports to scan",
    )

    # Add argument for default ports
    parser.add_argument(
        "-dp",
        "--default-ports",
        metavar="default_ports",
        type=bool,
        default=False,
        help="It enables PORTS by Default.",
    )

    # Add argument for descovering devices
    parser.add_argument(
        "-dd",
        "--discover-devices",
        metavar="discover_devices",
        type=bool,
        default=False,
        help="It discover available devices",
    )

    # Get arguments from command line
    args = parser.parse_args()

    # Get IP Address and ports to scan from arguments
    ip = args.ip
    if not validate_ip_address(ip):
        _ip, error = validate_by_domain_address(ip)
        if error:
            parser.error("Please insert valid domain or IP address")
        ip = _ip
    
    ports = args.ports
    def_ports = args.default_ports

    if not def_ports:
        if ports:
            ports = [int(port.strip()) for port in ports.split(",")]
        else:
            ports = [i for i in range(1, 65537)]
    else:
        print(colored("Using default ports", "yellow"))
        ports = [20, 21, 22, 53, 80, 123, 179, 443, 500, 587, 3389]

    # Run the selected function
    if args.syn_scan:
        print("Performing Syn Scan...")
        open_ports = syn_scan(ip, ports)
        print(
            f"Open ports: {', '.join(map(str, open_ports))}"
            if open_ports
            else "Open ports: None"
        )
    elif args.tcp_scan:
        print("Performing TCP Scan...")
        open_ports = tcp_connect_scan(ip, ports)
        print(f"Open ports: {', '.join(map(str, open_ports))}")
    elif args.ack_scan:
        print("Performing ACK Scan...")
        filtered_ports = ack_scan(ip, ports)
        print(
            f"Filtered ports: {', '.join(map(str, filtered_ports))}"
            if filtered_ports
            else "Filtered ports: None"
        )
    elif args.banner_grabbing:
        print("Performing Banner Grabbing...")
        banner = banner_grabbing(ip, ports[0])
        print(f"Banner: {banner}")
    elif args.http_header:
        print("Performing HTTP header...")
        headers = http_header_evaluation(ip)
        print(f"HTTP headers: {headers}")
    elif args.os_detection:
        os = os_detection(ip)
        print(f"Operating system: {os}")
    elif args.discover_devices:
        print("Performing Devices discovedred...")
    else:
        print("Please select a scan type")

def validate_ip_address(target_ip: str) -> bool:
    try:
        _ = ip_address(target_ip)
        print(colored(f"The IP address {target_ip} is valid.", "green"))
        return True
    except ValueError:
        print(colored(f"The IP address {target_ip} is not valid", "red"))
        return False

def validate_by_domain_address(ip_or_domain: str):
    try:
        # Check if the input is a valid IP address first
        ip_address(ip_or_domain)
        print(colored(f"The IP address {ip_or_domain} is valid", "green"))
        return ip_or_domain, True
    except ValueError:
        # If not a valid IP address, try resolving as a domain
        try:
            ip = socket.gethostbyname(ip_or_domain)
            print(colored(f"The domain {ip_or_domain} resolved to IP {ip} could be valid instead", "yellow"))
            return "", True
        except socket.gaierror:
            print(colored(f"The IP address or domain {ip_or_domain} is not valid", "red"))
            return "", False


def handler(signum, frame) -> None:
    options = ["y", ""]
    res = input("Ctrl-c was pressed. Do you really want to exit? ([y]/n): ").lower()
    if res in options:
        exit(1)


if __name__ == "__main__":
    signal.signal(signal.SIGINT, handler)
    main()