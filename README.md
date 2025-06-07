<h1>🔍 ScanSurge</h1>
<p>A Lightweight Network Scanner for Cybersecurity Enthusiasts.</p>

<p><strong>ScanSurge</strong> is a Python-based command-line interface (CLI) network scanner designed for host discovery, port scanning, and service detection. Developed by <strong>Sourish Chakraborty</strong> as a personal project, ScanSurge is an independent, ethical alternative to tools like Nmap. Tailored for cybersecurity students and enthusiasts, it offers a user-friendly experience for private, non-commercial use on authorized networks.</p>

<h2>📑 Table of Contents</h2>
<ul>
  <li><a href="#motivation">Project Motivation</a></li>
  <li><a href="#features">Features</a></li>
  <li><a href="#installation">Installation</a></li>
  <li><a href="#usage">Usage</a>
      <ol>
        <li><a href="#kali">Kali Linux Roadmap</a></li>
        <li><a href="#linux">Linux Roadmap</a></li>
        <li><a href="#windows">Windows Roadmap</a></li>
        <li><a href="#version">Version History</a></li>
      </ol>
  </li>
  <li><a href="#testing">Testing Environment</a></li>
  <li><a href="#roadmap">Roadmap</a></li>
  <li><a href="#legal">Legal and Ethical Use</a></li>
  <li><a href="#license">License</a></li>
  <li><a href="#contributing">Contributing</a></li>
  <li><a href="#acknowledgments">Acknowledgments</a></li>
  <li><a href="#author">Author</a></li>
</ul>

<h2 id="motivation">🎯 Project Motivation</h2>
<p>ScanSurge was created to empower cybersecurity learners with a simple, open-source tool for network exploration. As a cybersecurity student, I aimed to build a lightweight alternative to Nmap, focusing on core functionalities like host discovery and port scanning.</p>

<h2 id="features">✨ Features</h2>
<ul>
  <li>🔎 Host Discovery (like <code>nmap -sn</code>)</li>
  <li>🛠️ TCP & UDP Port Scanning</li>
  <li>🧠 Basic Banner Grabbing</li>
  <li>🧭 Interactive Menu Mode</li>
  <li>📄 Output in CSV/JSON/TXT</li>
  <li>⚙️ Minimal Dependencies (~200 lines)</li>
  <li>💻 Cross-platform Support</li>
</ul>

<h2 id="installation">📥 Installation</h2>
<h3>Prerequisites</h3>
<ul>
  <li>Python 3.8+</li>
  <li>Git</li>
  <li>Administrator Privileges</li>
</ul>

<h3>Setup</h3>
<pre><code>git clone https://github.com/yourusername/scansurge.git
cd scansurge
pip install -r requirements.txt</code></pre>

<h3>Dependencies</h3>
<p><code>scapy >= 2.4.5</code>, <code>ipaddress</code></p>

<h2 id="usage">🚀 Usage</h2>
<p>ScanSurge supports interactive and command-line modes. See roadmaps below:</p>

<h2 id="kali">🐉 Kali Linux Roadmap</h2>
<h3>Install Prerequisites</h3>
<pre><code>sudo apt-get update
sudo apt-get install python3 python3-pip git libpcap-dev</code></pre>

<h3>Setup and Interface</h3>
<pre><code>git clone https://github.com/yourusername/scansurge.git
cd scansurge
pip install -r requirements.txt
ip addr</code></pre>

<h3>Prepare Target</h3>
<pre><code>sudo python3 -m http.server 80
sudo systemctl start ssh
sudo ufw allow 80/tcp
sudo ufw allow 22/tcp
sudo ufw allow proto icmp</code></pre>

<h3>Run</h3>
<pre><code>sudo python3 scanner.py --interactive
# or
sudo python3 scanner.py -r &lt;network-range&gt; -p 80,22 --proto tcp --iface eth0 -t 3</code></pre>

<h2 id="linux">🐧 Linux Roadmap</h2>
<p>Same steps as Kali with interface adjustment (e.g., <code>enp0s3</code>).</p>

<h2 id="windows">🪟 Windows Roadmap</h2>
<h3>Install</h3>
<ul>
  <li>Python 3.8+ (Add to PATH)</li>
  <li>Git</li>
  <li>Npcap (default options)</li>
</ul>

<h3>Run</h3>
<pre><code>python scanner.py --interactive
# or
python scanner.py -r &lt;network-range&gt; -p 80,22 --proto tcp --iface "\Device\NPF_{UUID}" -t 3</code></pre>

<h2 id="version">📌 Version History</h2>
<ul>
  <li><strong>v1.0.2:</strong> Improved formatting, fixed multiple IP scanning.</li>
  <li><strong>v1.0.1:</strong> Interactive mode, custom timeouts, UDP added.</li>
  <li><strong>v1.0.0:</strong> Initial release with ARP scanning.</li>
</ul>

<h2 id="testing">🧪 Testing Environment</h2>
<ul>
  <li>6 devices on a private subnet</li>
  <li>Kali VM, Windows/Linux PCs</li>
  <li>Tools: VS Code, arp-scan</li>
</ul>

<h2 id="roadmap">🛣️ Roadmap</h2>
<ul>
  <li>OS Fingerprinting</li>
  <li>Advanced Service Detection</li>
  <li>GUI Version</li>
  <li>Async Scanning</li>
  <li>IPv6 Support</li>
</ul>

<h2 id="legal">⚖️ Legal and Ethical Use</h2>
<p>Use only on authorized networks. Violating terms may breach laws such as the CFAA.</p>

<h2 id="license">📝 License</h2>
<p><strong>ScanSurge Open License:</strong> Free for educational, non-commercial use. See <code>LICENSE</code>.</p>

<h2 id="contributing">🤝 Contributing</h2>
<ol>
  <li>Fork the repo</li>
  <li>Create a branch: <code>git checkout -b feature/new-feature</code></li>
  <li>Commit: <code>git commit -m "Add new feature"</code></li>
  <li>Push: <code>git push origin feature/new-feature</code></li>
  <li>Open a Pull Request</li>
</ol>
<p>Report issues under <code>Issues</code> tab.</p>

<h2 id="acknowledgments">🙏 Acknowledgments</h2>
<ul>
  <li>🔧 Tools: Python, Scapy</li>
  <li>🌐 Community: Cybersecurity Forums</li>
</ul>

<h2 id="author">👤 Author</h2>
<p><strong>Sourish Chakraborty</strong><br>
Cybersecurity Student | Network Security Enthusiast</p>
<p>GitHub: <a href="https://github.com/Sourish-Chakraborty04" target="_blank">Sourish-Chakraborty04</a></p>

</body>
</html>
