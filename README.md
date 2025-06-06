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

# ScanSurge
A Lightweight Network Scanner for Cybersecurity Enthusiasts
ScanSurge is a Python-based command-line interface (CLI) network scanner designed for host discovery, port scanning, and service detection. Developed by Sourish Chakraborty as a personal project, ScanSurge is an independent, ethical alternative to tools like Nmap, inspired by Linus Torvalds’ DIY ethos in creating Linux. Tailored for cybersecurity students and enthusiasts, it offers a user-friendly experience for private, non-commercial use on authorized networks.
  
##Table of Contents

- **Project Motivation**
- **Features**
- **Installation**
- **Usage**
1. Kali Linux Roadmap
2. Linux Roadmap
3. Windows Roadmap


- **Version History**
- **Testing Environment**
- **Roadmap**
- **Legal and Ethical Use**
- **License**
- **Contributing**
- **Acknowledgments**
- **Author**

##Project Motivation
ScanSurge was created to empower cybersecurity learners with a simple, open-source tool for network exploration. As a cybersecurity student, I aimed to build a lightweight alternative to Nmap, focusing on core functionalities like host discovery and port scanning. By maintaining a clear version history through Git branches, ScanSurge showcases my development journey, from initial ARP scanning to advanced TCP/UDP capabilities, making it a valuable portfolio piece for technical interviews.

##Features

- **Host Discovery**: Identifies active devices using ARP requests, similar to nmap -sn.
- **Port Scanning**: Scans TCP and UDP ports (e.g., 80, 22, 53) to detect open services.
- **Service Detection**: Performs basic banner grabbing to identify running services.
- **Interactive Mode**: Offers a menu-driven interface for selecting scan types, IP ranges, timeouts, and ports.
- **Flexible Output**: Saves results in CSV, JSON, or plain text formats.
- **Lightweight Design**: Minimal dependencies (~200 lines of code).
- **Cross-Platform**: Compatible with Kali Linux, general Linux, Windows, and virtualized environments.

##Installation
###Prerequisites

1. Python 3.8+: Install from python.org.
2. Git: For cloning the repository.
3. Administrative Privileges: Required for raw socket operations.

General Steps

1. Clone the Repository:git clone https://github.com/yourusername/scansurge.git
```bash
cd scansurge


2. Install Dependencies:
```bash
pip install -r requirements.txt


3. Dependencies: scapy>=2.4.5, ipaddress.



###Platform-Specific Setup

Kali Linux: See Kali Linux Roadmap.
Linux (e.g., Ubuntu): See Linux Roadmap.
Windows: See Windows Roadmap.

##Usage
ScanSurge supports interactive and command-line modes. Below are detailed roadmaps for each supported operating system.
###Kali Linux Roadmap
Kali Linux is the primary development platform for ScanSurge, optimized for cybersecurity tasks.

Install Prerequisites:sudo apt-get update
```bash
sudo apt-get install python3 python3-pip git libpcap-dev


1. Clone and Set Up:
```bash
git clone https://github.com/yourusername/scansurge.git
cd scansurge
pip install -r requirements.txt


2. Configure Network (VirtualBox):
Open VirtualBox > Settings > Network > Adapter 1.
Set to Bridged Adapter, select host’s active interface.
Enable Promiscuous Mode: Allow All.
Check “Cable Connected.”
Verify interface:ip addr


Note the interface name (e.g., eth0).




3. Prepare Target:
Start services on a target device:sudo python3 -m http.server 80
sudo systemctl start ssh


4. Allow traffic:sudo ufw allow 80/tcp
sudo ufw allow 22/tcp
sudo ufw allow proto icmp


5. Test connectivity:nc -zv <target-ip> 80




6. Run ScanSurge:
Interactive Mode:sudo python3 scanner.py --interactive


Select option (e.g., 2 for TCP Port Scan).
Enter <target-ip>, number of IPs, timeout, ports (e.g., 80,22), and interface (e.g., eth0).


Command-Line Mode:sudo python3 scanner.py -r <network-range> -p 80,22 --proto tcp --iface eth0 -t 3




7. View Results:cat scansurge_results.csv


8. Troubleshoot:
Check network:sudo arp-scan -l


Disable firewall temporarily:sudo ufw disable





###Linux Roadmap
For general Linux distributions (e.g., Ubuntu, Debian).

1. Install Prerequisites:sudo apt-get update
```bash
sudo apt-get install python3 python3-pip git libpcap-dev


2. Clone and Set Up:
```bash
git clone https://github.com/yourusername/scansurge.git
cd scansurge
pip install -r requirements.txt


Identify Interface:ip link


Note the active interface (e.g., enp0s3).


3. Prepare Target:
On a target device:sudo python3 -m http.server 80
sudo systemctl start ssh


4. Allow traffic:sudo ufw allow 80/tcp
sudo ufw allow 22/tcp
sudo ufw allow proto icmp


Test:nc -zv <target-ip> 80




5. Run ScanSurge:
Interactive Mode:sudo python3 scanner.py --interactive


Command-Line Mode:sudo python3 scanner.py -r <network-range> -p 80,22 --proto tcp --iface enp0s3 -t 3




6. View Results:cat scansurge_results.csv


Troubleshoot:
Install arp-scan:sudo apt-get install arp-scan
sudo arp-scan -l


Check firewall:sudo iptables -L





###Windows Roadmap
ScanSurge runs on Windows with Npcap for packet capture.

1. Install Prerequisites:
Download Python 3.8+ from python.org. Ensure pip and Add to PATH are selected.
Install Git from git-scm.com.
Download Npcap from npcap.com. Install with default options.


2. Clone and Set Up:
Open Command Prompt or PowerShell as Administrator:git clone https://github.com/yourusername/scansurge.git
cd scansurge
pip install -r requirements.txt




3. Identify Interface:
Run:ipconfig


Note the adapter name (e.g., Ethernet).
Use scapy to find Npcap interface:python -c "from scapy.all import conf; print(conf.ifaces)"


Look for the Npcap interface name (e.g., \Device\NPF_{UUID}).




4. Prepare Target:
On a target device (Windows/Linux):
Start a web server (e.g., use Python or install Apache).
Enable SSH if available.


5. Allow traffic in Windows Defender Firewall:
Control Panel > Windows Defender Firewall > Advanced Settings.
Create inbound rules for TCP 80, 22, and ICMPv4.


Test:ncat -zv <target-ip> 80




6. Run ScanSurge:
Interactive Mode (as Administrator):python scanner.py --interactive


Command-Line Mode:python scanner.py -r <network-range> -p 80,22 --proto tcp --iface "\Device\NPF_{UUID}" -t 3




7. View Results:type scansurge_results.csv


8. Troubleshoot:
Verify Npcap:scapy


Check firewall:netsh advfirewall show allprofiles





##Version History
ScanSurge’s development is tracked through Git branches and releases:

###v1.0.2 (main branch, release):
Fixed TCP port scanning for multiple IPs.
Improved output formatting.
Optimized timeout handling.


###v1.0.1 (v1.0.1 branch, release):
Introduced interactive mode.
Added custom IP counts and timeouts.
Enhanced TCP/UDP scanning.


###v1.0.0 (planned v1.0.0 branch):
Initial release with ARP host discovery.



###Accessing Versions:

Latest: Clone main or download from releases.
Older: Checkout branches (e.g., git checkout v1.0.1) or download from releases.

Testing Environment
Developed in a controlled home lab:

Network: Six PCs on a private subnet, connected via a router.
Devices: Kali Linux VM (VirtualBox, Bridged Adapter), Windows/Linux PCs.
Tools: VS Code, arp-scan for validation.
Setup: Firewalls allow ICMP, ARP, TCP/UDP; services (HTTP, SSH) enabled.

##Roadmap

1. OS Fingerprinting: Detect operating systems.
2. Advanced Service Detection: Expand banner grabbing.
3. GUI Option: Graphical interface for accessibility.
4. Performance: Asynchronous scanning for larger networks.
5. IPv6 Support: Add IPv6 compatibility.

##Legal and Ethical Use
ScanSurge is for educational and private use only on authorized networks. Unauthorized scanning may violate laws like the U.S. Computer Fraud and Abuse Act (CFAA). Always obtain permission before scanning.
##License
ScanSurge Open License: Free for non-commercial use. See LICENSE.
##Contributing

- **Fork the repository.**
- **Create a branch (git checkout -b feature/new-feature).
- **Commit changes (git commit -m "Add new feature").
- **Push (git push origin feature/new-feature).
Open a pull request.

Report issues at Issues.
##Acknowledgments

Tools: Scapy, Python.
Community: Cybersecurity forums.

##Author
Sourish Chakraborty Cybersecurity Student | Network Security Enthusiast  

GitHub: Sourish-Chakraborty04
