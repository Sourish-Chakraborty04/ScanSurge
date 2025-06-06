# ScanSurge
A lightweight, Python-based CLI network scanner for host discovery, port scanning, and service detection. Built by Sourish Chakraborty as a personal project to create an independent, ethical alternative to Nmap. ScanSurge is designed for cybersecurity students and enthusiasts who want a simple, powerful tool for network exploration.

## Features
- **Host Discovery**: Finds active devices using ARP requests (similar to `nmap -sn`).
- **Port Scanning**: Scans TCP and UDP ports (e.g., 80, 22, 53) to detect open ports.
- **Service Detection**: Identifies services via banner grabbing (akin to `nmap -sV`).
- **Output Formats**: Saves results in CSV, JSON, or text for flexibility.
- **User-Friendly**: Simple CLI arguments for beginners, avoiding Nmap’s complexity.
- **Lightweight**: Minimal dependencies and ~150 lines of code.

## Installation
1. Clone the repository: `git clone https://github.com/Sourish-Chakraborty04/ScanSurge.git`
2. Install dependencies: `pip install -r requirements.txt`
3. Run as root (due to raw packet access): `sudo python3 scanner.py`

## Usage
```bash
# Check version
sudo python3 scanner.py --version

# Default host discovery (192.168.1.0/24, 3s timeout)
sudo python3 scanner.py

# Custom IP range, timeout, and output
sudo python3 scanner.py -r 192.168.0.0/24 -t 5 -o myresults

# Scan TCP ports
sudo python3 scanner.py -r 192.168.1.0/24 -p 80,22,443 --proto tcp

# Scan TCP and UDP ports, save as JSON
sudo python3 scanner.py -r 192.168.1.0/24 -p 80,53 --proto both --format json
