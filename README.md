  <h1>⚡ ScanSurge</h1>
  <p><strong>A Lightweight Network Scanner for Cybersecurity Enthusiasts</strong></p>

  <p>
    ScanSurge is a Python-based CLI network scanner for host discovery and port scanning. Developed by <strong>Sourish Chakraborty</strong>, it’s an ethical alternative to Nmap for cybersecurity students, built for private, non-commercial use.
  </p>

  <h2>🚀 Features</h2>
  <ul>
    <li><strong>Host Discovery:</strong> ARP-based device detection.</li>
    <li><strong>Port Scanning:</strong> TCP and UDP scans (e.g., ports 80, 22).</li>
    <li><strong>Interactive Mode:</strong> Menu-driven interface for scan configuration.</li>
    <li><strong>Flexible Output:</strong> Results in CSV format.</li>
    <li><strong>Lightweight:</strong> ~150 lines of code.</li>
    <li><strong>Cross-Platform:</strong> Linux, Windows, VirtualBox.</li>
  </ul>

  <h2>🔧 Installation</h2>

  <h3>📦 Prerequisites</h3>
  <ul>
    <li>Python 3.8+</li>
    <li>Git</li>
    <li>Administrative privileges</li>
  </ul>

  <h3>📥 Steps</h3>
  <pre><code>
git clone https://github.com/Sourish-Chakraborty04/scansurge.git
cd scansurge
pip install -r requirements.txt
  </code></pre>

  <p><strong>Dependencies:</strong> <code>scapy&gt;=2.4.5</code>, <code>ipaddress</code></p>

  <h3>🖥️ Platform Setup</h3>
  <ul>
    <li><strong>Linux:</strong> Install libpcap: <code>sudo apt-get install libpcap-dev</code></li>
    <li><strong>Windows:</strong> Install Npcap from <a href="https://npcap.com" target="_blank">npcap.com</a></li>
    <li><strong>VirtualBox:</strong> Use Bridged Adapter, enable Promiscuous Mode</li>
  </ul>

  <h2>🛠️ Usage</h2>

  <h3>💻 Interactive Mode</h3>
  <pre><code>sudo python3 scanner.py --interactive</code></pre>
  <p>
    Select scan type (e.g., TCP Port Scan).<br>
    Enter <code>&lt;target-ip&gt;</code>, ports (e.g., <code>80,22</code>), timeout, and interface (e.g., <code>eth0</code>).
  </p>

  <h4>🔎 Example Output:</h4>
  <pre><code>
Starting TCP Port Scan...
DEBUG: Port 80/tcp on &lt;target-ip&gt; is OPEN
Discovered Devices:
IP Address      MAC Address      Hostname      Open Ports
-------------------------------------------------------
&lt;target-ip&gt;     Unknown          Unknown       80 (TCP)
Results saved to scansurge_results.csv
  </code></pre>

  <h3>📟 Command-Line Mode</h3>
  <pre><code>sudo python3 scanner.py -r &lt;network-range&gt; -p 80,22 --proto tcp --iface eth0 -t 3</code></pre>

  <ul>
    <li><code>--proto</code>: tcp, udp, or both</li>
    <li><code>-p</code>: Comma-separated ports</li>
  </ul>

  <h2>🧪 Testing Environment</h2>
  <ul>
    <li><strong>Network:</strong> Private subnet with six PCs</li>
    <li><strong>Devices:</strong> Kali Linux VM, Windows/Linux PCs</li>
    <li><strong>Setup:</strong> Firewalls allow ICMP, ARP, TCP/UDP</li>
  </ul>

  <h2>⚖️ Legal and Ethical Use</h2>
  <p><strong>For educational use on authorized networks only.</strong></p>

  <h2>📝 License</h2>
  <p>ScanSurge Open License. See <code>LICENSE</code>.</p>

  <h2>👨‍💻 Author</h2>
  <p>
    <strong>Sourish Chakraborty</strong><br>
    Cybersecurity Student<br>
    🔗 GitHub: <a href="https://github.com/Sourish-Chakraborty04" target="_blank">Sourish-Chakraborty04</a>
  </p>
