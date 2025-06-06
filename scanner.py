import argparse
import socket
import os
import sys
import platform
import ctypes
from scapy.all import ARP, Ether, srp, TCP, UDP, conf
from utils import print_results, save_results
from concurrent.futures import ThreadPoolExecutor
import ipaddress

__version__ = "1.0.1"

def display_banner():
    """Display ScanSurge activation banner in the terminal."""
    banner = r"""
╔══════════════════════════════════════════════════════════════════════════════════╗
║                                                                                  ║
║    _______ _______ _______ _          _______         _______ _______ _______    ║
║   (  ____ (  ____ (  ___  ( (    /|  (  ____ |\     /(  ____ (  ____ (  ____ \   ║
║   | (    \| (    \| (   ) |  \  ( |  | (    \| )   ( | (    )| (    \| (    \/   ║
║   | (_____| |     | (___) |   \ | |  | (_____| |   | | (____)| |     | (__       ║
║   (_____  | |     |  ___  | (\ \) |  (_____  | |   | |     __| | ____|  __)      ║
║         ) | |     | (   ) | | \   |        ) | |   | | (\ (  | | \_  | (         ║
║   /\____) | (____/| )   ( | )  \  |  /\____) | (___) | ) \ \_| (___) | (____/\   ║
║   \_______(_______|/     \|/    )_)  \_______(_______|/   \__(_______(_______/   ║
║                                                                                  ║
║                                                                                  ║
║                                     v1.0.1                                       ║
║                           Lightweight Network Scanner                            ║
║                           Built by Sourish Chakraborty                           ║
║                                                                                  ║
╚══════════════════════════════════════════════════════════════════════════════════╝
"""
    print(banner.strip())

def is_admin():
    """Check if the script is running with administrative privileges."""
    if platform.system() == "Windows":
        try:
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except:
            return False
    else:
        try:
            return os.geteuid() == 0
        except AttributeError:
            return False

def scan_ip(ip, timeout, iface):
    """Scan a single IP for ARP response."""
    try:
        arp = ARP(pdst=ip)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether/arp
        result = srp(packet, timeout=timeout/256, iface=iface, verbose=0)[0]
        for _, received in result:
            try:
                hostname = socket.gethostbyaddr(received.psrc)[0]
            except:
                hostname = "Unknown"
            return {"ip": received.psrc, "mac": received.hwsrc, "hostname": hostname}
    except:
        return None
    return None

def scan_network(ip_range, timeout=3, iface=None, max_ips=256):
    """Scan network for active devices using ARP requests."""
    conf.use_pcap = True
    conf.verb = 0
    print(f"DEBUG: Sending ARP requests to {ip_range} with timeout {timeout}s on interface {iface or 'default'}")
    try:
        network = ipaddress.ip_network(ip_range, strict=False)
        ips = [str(ip) for ip in network.hosts()][:max_ips]
        devices = []
        print(f"DEBUG: Scanning {len(ips)} IPs")
        with ThreadPoolExecutor(max_workers=50) as executor:
            results = executor.map(lambda ip: scan_ip(ip, timeout, iface), ips)
            devices = [d for d in results if d]
        print(f"DEBUG: Received {len(devices)} ARP responses")
        print(f"DEBUG: Found {len(devices)} devices")
        return devices
    except Exception as e:
        print(f"DEBUG: Error during host discovery: {e}")
        return []

def scan_port(ip, port, protocol="tcp", timeout=2):
    """Scan a specific port on a target IP (TCP or UDP)."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM if protocol == "tcp" else socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, port))
        sock.close()
        if result == 0:
            print(f"DEBUG: Port {port}/{protocol} on {ip} is OPEN")
            return True
        else:
            print(f"DEBUG: Port {port}/{protocol} on {ip} is CLOSED or filtered (code: {result})")
            return False
    except socket.error as e:
        print(f"DEBUG: Error scanning {ip}:{port}/{protocol}: {e}")
        return False

def detect_service(ip, port, protocol="tcp", timeout=2):
    """Basic service detection via banner grabbing."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM if protocol == "tcp" else socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.connect((ip, port))
        sock.send(b"GET / HTTP/1.0\r\n\r\n" if port in [80, 443] else b"")
        banner = sock.recv(1024).decode(errors="ignore").strip()[:50]
        sock.close()
        return banner or "Unknown"
    except:
        return "Unknown"

def scan_devices(devices, ports=None, protocols=None, timeout=2):
    """Scan ports and services for discovered devices."""
    if not ports:
        print("DEBUG: No ports specified, skipping port scanning")
        return devices
    protocols = protocols or ["tcp"]
    print(f"DEBUG: Scanning ports {ports} with protocols {protocols} on {len(devices)} devices")
    for device in devices:
        device["open_ports"] = {}
        for protocol in protocols:
            device["open_ports"][protocol] = []
            for port in ports:
                print(f"DEBUG: Scanning {device['ip']}:{port}/{protocol}")
                if scan_port(device["ip"], port, protocol, timeout):
                    service = detect_service(device["ip"], port, protocol, timeout)
                    device["open_ports"][protocol].append({"port": port, "service": service})
    return devices

def interactive_mode():
    """Interactive menu for scan type selection and input."""
    print("\nScanSurge Interactive Mode")
    print("Select a scan type:")
    print("1. ARP Host Discovery")
    print("2. TCP Port Scan")
    print("3. UDP Port Scan")
    print("4. Full Scan (ARP + TCP/UDP + Service Detection)")
    print("5. Exit")
    
    while True:
        choice = input("\nEnter option (1-5): ").strip()
        if choice in ['1', '2', '3', '4', '5']:
            break
        print("Invalid option. Please enter 1, 2, 3, 4, or 5.")

    if choice == '5':
        print("Exiting ScanSurge.")
        sys.exit(0)

    # Get target IP or range
    while True:
        ip_range = input("Enter target IP or range (e.g., 192.168.0.102 or 192.168.0.0/24): ").strip()
        try:
            ipaddress.ip_network(ip_range, strict=False)
            break
        except ValueError:
            print("Invalid IP or range. Try again.")

    # Get number of IPs to scan
    while True:
        try:
            max_ips = int(input("Enter number of IPs to scan (1-256, default 256): ").strip() or 256)
            if 1 <= max_ips <= 256:
                break
            print("Please enter a number between 1 and 256.")
        except ValueError:
            print("Invalid input. Enter a number.")

    # Get timeout
    while True:
        try:
            timeout = float(input("Enter total scan timeout in seconds (default 3): ").strip() or 3)
            if timeout > 0:
                break
            print("Timeout must be positive.")
        except ValueError:
            print("Invalid input. Enter a number.")

    # Get ports for TCP/UDP scans
    ports = None
    if choice in ['2', '3', '4']:
        while True:
            ports_input = input("Enter ports to scan (comma-separated, e.g., 80,22, default 80,22,443): ").strip() or "80,22,443"
            try:
                ports = [int(p) for p in ports_input.split(",")]
                if all(1 <= p <= 65535 for p in ports):
                    break
                print("Ports must be between 1 and 65535.")
            except ValueError:
                print("Invalid ports. Use comma-separated numbers.")

    # Get interface
    iface = input("Enter network interface (e.g., eth0, default auto): ").strip() or None

    # Execute scan
    protocols = ["tcp"] if choice == '2' else ["udp"] if choice == '3' else ["tcp", "udp"]
    devices = []

    if choice in ['1', '4']:
        print(f"\nStarting ARP Host Discovery on {ip_range}...")
        devices = scan_network(ip_range, timeout, iface, max_ips)
        if not devices:
            print("No devices found.")
            if choice == '1':
                sys.exit(1)

    if choice in ['2', '3']:
        # For TCP/UDP only, assume single IP or prompt for devices
        try:
            network = ipaddress.ip_network(ip_range, strict=False)
            devices = [{"ip": str(ip), "mac": "Unknown", "hostname": "Unknown"} for ip in list(network.hosts())[:max_ips]]
        except:
            devices = [{"ip": ip_range, "mac": "Unknown", "hostname": "Unknown"}]

    if choice in ['2', '3', '4']:
        print(f"\nStarting {protocols[0].upper()} Port Scan on {len(devices)} devices...")
        devices = scan_devices(devices, ports, protocols, timeout/2)

    print_results(devices, ports, protocols=protocols[0] if choice in ['2', '3'] else "both")
    save_results(devices, "scansurge_results.csv", ports, protocols=protocols[0] if choice in ['2', '3'] else "both", format="csv")

def main():
    parser = argparse.ArgumentParser(description="ScanSurge: A lightweight network scanner for host and port discovery.")
    parser.add_argument("--version", action="version", version=f"ScanSurge v{__version__}")
    parser.add_argument("-r", "--range", help="IP range to scan (e.g., 192.168.0.0/24)")
    parser.add_argument("-t", "--timeout", type=float, help="Total scan timeout in seconds")
    parser.add_argument("-p", "--ports", help="Comma-separated ports to scan (e.g., 80,22)")
    parser.add_argument("--proto", choices=["tcp", "udp", "both"], help="Protocol(s) to scan")
    parser.add_argument("-o", "--output", default="scansurge_results", help="Output file prefix")
    parser.add_argument("--format", default="csv", choices=["csv", "json", "txt"], help="Output format")
    parser.add_argument("--iface", help="Network interface to use (e.g., eth0)")
    parser.add_argument("--interactive", action="store_true", help="Run in interactive mode")
    args = parser.parse_args()

    if not is_admin():
        print("Error: ScanSurge requires administrative privileges. Run with sudo.")
        sys.exit(1)

    display_banner()

    if args.interactive or not any([args.range, args.ports, args.proto]):
        interactive_mode()
    else:
        protocols = ["tcp", "udp"] if args.proto == "both" else [args.proto or "tcp"]
        ports = [int(p) for p in args.ports.split(",")] if args.ports else None
        timeout = args.timeout or 3
        print(f"Scanning {args.range} with total timeout {timeout}s...")
        devices = scan_network(args.range, timeout, args.iface)
        if not devices:
            print("No devices found.")
            sys.exit(1)
        devices = scan_devices(devices, ports, protocols, timeout/2)
        print_results(devices, ports, protocols=args)
        save_results(devices, f"{args.output}.{args.format}", ports, protocols=args, format=args.format)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nScan interrupted.")
        sys.exit(0)