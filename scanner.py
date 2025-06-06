import argparse
import socket
import os
from scapy.all import ARP, Ether, srp, TCP, UDP
import sys
from utils import print_results, save_results

__version__ = "1.0.0"

def display_banner():
    """Display ScanSurge activation banner in the terminal."""
    banner = """
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
    ║                                     v1.0.0                                       ║
    ║                           Lightweight Network Scanner                            ║
    ║                           Built by Sourish Chakraborty                           ║
    ║                                                                                  ║
    ╚══════════════════════════════════════════════════════════════════════════════════╝
    """
    print(banner)

def scan_network(ip_range, timeout=3):
    """Scan network for active devices using ARP requests."""
    try:
        arp = ARP(pdst=ip_range)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether/arp
        result = srp(packet, timeout=timeout, verbose=0)[0]
        devices = []
        for sent, received in result:
            try:
                hostname = socket.gethostbyaddr(received.psrc)[0]
            except:
                hostname = "Unknown"
            devices.append({"ip": received.psrc, "mac": received.hwsrc, "hostname": hostname})
        return devices
    except Exception as e:
        print(f"Error during host discovery: {e}")
        return []

def scan_port(ip, port, protocol="tcp", timeout=1):
    """Scan a specific port on a target IP (TCP or UDP)."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM if protocol == "tcp" else socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, port))
        sock.close()
        return result == 0
    except:
        return False

def detect_service(ip, port, protocol="tcp", timeout=1):
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

def scan_devices(devices, ports=None, protocols=None, timeout=1):
    """Scan ports and services for discovered devices."""
    if not ports:
        return devices
    protocols = protocols or ["tcp"]
    for device in devices:
        device["open_ports"] = {}
        for protocol in protocols:
            device["open_ports"][protocol] = []
            for port in ports:
                if scan_port(device["ip"], port, protocol, timeout):
                    service = detect_service(device["ip"], port, protocol, timeout)
                    device["open_ports"][protocol].append({"port": port, "service": service})
    return devices

def main():
    parser = argparse.ArgumentParser(description="ScanSurge: A lightweight network scanner for host and port discovery.")
    parser.add_argument("--version", action="version", version=f"ScanSurge v{__version__}")
    parser.add_argument("-r", "--range", default="192.168.1.0/24", help="IP range to scan (e.g., 192.168.1.0/24)")
    parser.add_argument("-t", "--timeout", type=int, default=3, help="Scan timeout in seconds")
    parser.add_argument("-p", "--ports", help="Comma-separated ports to scan (e.g., 80,22)")
    parser.add_argument("--proto", default="tcp", choices=["tcp", "udp", "both"], help="Protocol(s) to scan (tcp, udp, or both)")
    parser.add_argument("-o", "--output", default="scansurge_results", help="Output file prefix")
    parser.add_argument("--format", default="csv", choices=["csv", "json", "txt"], help="Output format (csv, json, txt)")
    args = parser.parse_args()

    if os.geteuid() != 0:
        print("Error: ScanSurge requires root privileges. Run with sudo.")
        sys.exit(1)

    display_banner()
    protocols = ["tcp", "udp"] if args.proto == "both" else [args.proto]
    ports = [int(p) for p in args.ports.split(",")] if args.ports else None

    print(f"Scanning {args.range} with timeout {args.timeout}s...")
    devices = scan_network(args.range, args.timeout)
    if not devices:
        print("No devices found.")
        sys.exit(1)

    devices = scan_devices(devices, ports, protocols, args.timeout)
    print_results(devices, ports, protocols)
    save_results(devices, f"{args.output}.{args.format}", ports, protocols, args.format)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nScan interrupted.")
        sys.exit(0)