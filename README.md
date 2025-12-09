# 🎯 NULL-CLI

<div align="center">

```
███╗   ██╗██╗   ██╗██╗     ██╗           ██████╗██╗     ██╗
████╗  ██║██║   ██║██║     ██║          ██╔════╝██║     ██║
██╔██╗ ██║██║   ██║██║     ██║     █████╗██║     ██║     ██║
██║╚██╗██║██║   ██║██║     ██║     ╚════╝██║     ██║     ██║
██║ ╚████║╚██████╔╝███████╗███████╗     ╚██████╗███████╗██║
╚═╝  ╚═══╝ ╚═════╝ ╚══════╝╚══════╝      ╚═════╝╚══════╝╚═╝
```

**🎓 Safely learn offensive security tools without the legal risk**

[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Educational](https://img.shields.io/badge/purpose-educational-brightgreen.svg)](https://github.com/4fqr/null-cli)

</div>

---

## 🌟 What is NULL-CLI?

**NULL-CLI** is a safe, educational simulation of popular Kali Linux security tools. It provides **100% realistic output** without performing any actual network operations or exploits. Perfect for:

- 🎓 **Students** learning cybersecurity concepts without access to lab environments
- 👨‍🏫 **Educators** demonstrating security tools safely in classrooms
- 🔬 **Researchers** prototyping security workflows without ethical concerns
- 🧪 **Developers** testing security integrations without infrastructure
- 📚 **Security Enthusiasts** practicing tool usage before certification exams

> **No network traffic. No exploits. No legal risk. Just learning.**

---

## ✨ Features

### Core Features
- ✅ **100% Safe Simulation** - Zero network traffic, zero exploits, zero real system changes
- ✅ **Realistic Output** - Matches actual tool output with context-aware variations
- ✅ **8 Security Tools** - Comprehensive coverage of offensive security toolkit
- ✅ **Educational Mode** - Flag-by-flag explanations better than man pages
- ✅ **Works Offline** - No API keys, no internet connection required
- ✅ **Cross-Platform** - Linux, macOS, Windows (WSL supported)

### User Experience
- 🎨 **Beautiful Terminal UI** - Rich formatting with colors, tables, and ASCII art
- 🚀 **Beginner-Friendly** - Interactive first-run setup with guided tour
- 📊 **Command History** - Track your learning progress with timestamps
- ⚙️ **Configurable** - Educational mode, paranoia mode, favorite tools
- 🔐 **Paranoia Mode** - Require confirmation before simulating dangerous commands

### Technical Features
- 🎲 **Dynamic Simulation** - Randomized outputs for realistic variation
- 🌐 **RFC 5737 Compliance** - Uses only non-routable test IP addresses
- 📝 **Comprehensive Logging** - All simulations logged for review
- 🎯 **Context-Aware** - Educational info adapts to flags you actually use

---

## 🛠️ Supported Tools

| Tool | Category | Description | Accuracy | Educational |
|------|----------|-------------|----------|-------------|
| **nmap** | Network Scanner | Port scanning, OS detection, service enumeration | ★★★★★ | ✅ Comprehensive |
| **metasploit** | Exploitation | Exploit framework with msfconsole workflow | ★★★★★ | ✅ Complete |
| **hydra** | Brute-Force | Password attacks on 50+ protocols | ★★★★★ | ✅ Full coverage |
| **john** | Hash Cracking | Password hash cracking (dictionary, brute-force) | ★★★★★ | ✅ All modes |
| **sqlmap** | Web Security | SQL injection detection and exploitation | ★★★★★ | ✅ All techniques |
| **nikto** | Web Scanner | Web server vulnerability scanning | ★★★★☆ | ✅ Complete |
| **gobuster** | Enumeration | Directory/file brute-forcing | ★★★★★ | ✅ All modes |
| **wpscan** | CMS Security | WordPress security scanning | ★★★★☆ | ✅ Full features |

**8 tools fully implemented!** Each tool supports:
- Multiple command-line flags and options
- Context-aware educational explanations
- Realistic output with random variations
- Legal/ethical implications clearly stated

---

## 📦 Installation & Setup

### System Requirements

- **Python**: 3.9 or higher
- **Operating Systems**: Linux, macOS, Windows (10/11), WSL
- **Disk Space**: ~50 MB (including dependencies)
- **Internet**: Required only for initial installation

### 🐧 Linux Installation

#### Ubuntu/Debian

```bash
# Update package list
sudo apt update

# Install Python 3.9+ (if not already installed)
sudo apt install python3 python3-pip python3-venv -y

# Clone the repository
git clone https://github.com/4fqr/null-cli.git
cd null-cli

# Create virtual environment (recommended)
python3 -m venv .venv

# Activate virtual environment
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Install in editable mode (development)
pip install -e .

# OR install from PyPI (when available)
# pip install null-cli
```

#### Fedora/RHEL/CentOS

```bash
# Install Python and development tools
sudo dnf install python3 python3-pip python3-virtualenv -y

# Clone repository
git clone https://github.com/4fqr/null-cli.git
cd null-cli

# Create and activate virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install
pip install -r requirements.txt
pip install -e .
```

#### Arch Linux

```bash
# Install Python
sudo pacman -S python python-pip python-virtualenv

# Clone and setup
git clone https://github.com/4fqr/null-cli.git
cd null-cli
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
pip install -e .
```

### 🍎 macOS Installation

#### Using Homebrew (Recommended)

```bash
# Install Homebrew (if not installed)
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Install Python 3.9+
brew install python@3.11

# Clone repository
git clone https://github.com/4fqr/null-cli.git
cd null-cli

# Create virtual environment
python3 -m venv .venv

# Activate virtual environment
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt
pip install -e .
```

#### Using Python.org Installer

```bash
# Download Python from https://www.python.org/downloads/macos/
# Install Python 3.11+ using the downloaded .pkg file

# Open Terminal and verify installation
python3 --version

# Clone repository
git clone https://github.com/4fqr/null-cli.git
cd null-cli

# Create and activate virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install
pip install -r requirements.txt
pip install -e .
```

### 🪟 Windows Installation

#### Method 1: Windows PowerShell (Recommended)

```powershell
# Install Python from Microsoft Store or python.org
# Download: https://www.python.org/downloads/windows/
# During installation, CHECK "Add Python to PATH"

# Verify Python installation
python --version

# Clone repository (requires Git for Windows)
git clone https://github.com/4fqr/null-cli.git
cd null-cli

# Create virtual environment
python -m venv .venv

# Activate virtual environment (PowerShell)
.\.venv\Scripts\Activate.ps1

# If you get execution policy error, run:
# Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser

# Install dependencies
pip install -r requirements.txt
pip install -e .
```

#### Method 2: Command Prompt (cmd)

```cmd
# After installing Python from python.org

# Navigate to your projects folder
cd C:\Users\YourName\Documents

# Clone repository
git clone https://github.com/4fqr/null-cli.git
cd null-cli

# Create virtual environment
python -m venv .venv

# Activate virtual environment (Command Prompt)
.venv\Scripts\activate.bat

# Install
pip install -r requirements.txt
pip install -e .
```

### 🐳 Windows Subsystem for Linux (WSL)

```bash
# Install WSL2 (PowerShell as Administrator)
wsl --install

# Restart computer, then open WSL Ubuntu

# Update and install Python
sudo apt update
sudo apt install python3 python3-pip python3-venv git -y

# Follow Linux Ubuntu installation steps above
git clone https://github.com/4fqr/null-cli.git
cd null-cli
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
pip install -e .
```

### 🐳 Docker Installation (All Platforms)

```bash
# Clone repository
git clone https://github.com/4fqr/null-cli.git
cd null-cli

# Build Docker image
docker build -t null-cli .

# Run container
docker run -it null-cli

# Or run specific command
docker run -it null-cli use nmap -sV 192.0.2.1
```

---

## 🚀 Quick Start Guide

### First Run Experience

**Linux/macOS:**
```bash
# Activate virtual environment (if not already active)
source .venv/bin/activate

# Run null-cli
python -m null_cli.cli
```

**Windows PowerShell:**
```powershell
# Activate virtual environment
.\.venv\Scripts\Activate.ps1

# Run null-cli
python -m null_cli.cli
```

**What happens on first run:**
1. 🎨 Beautiful ASCII banner displays
2. 📋 Table of all 8 supported tools shown
3. ❓ You're asked to pick a favorite tool to try
4. 🎓 Option to enable educational mode (recommended for beginners)
5. 🔐 Option to enable paranoia mode (extra confirmation)
6. ⚡ Quick example command demonstrated

### Basic Commands

```bash
# View help
python -m null_cli.cli --help

# List all tools
python -m null_cli.cli

# Simulate a tool
python -m null_cli.cli use <tool> [flags]

# View configuration
python -m null_cli.cli config-cmd

# View command history
python -m null_cli.cli history

# Reset to defaults
python -m null_cli.cli reset
```

---

## 💡 Usage Examples

### Example 1: Nmap Port Scanning

**Basic scan:**
```bash
python -m null_cli.cli use nmap -sV 192.0.2.1
```

**Comprehensive scan with OS detection:**
```bash
python -m null_cli.cli use nmap -A -T4 -p- 192.0.2.1
```

**Stealth scan with specific ports:**
```bash
python -m null_cli.cli use nmap -sS -p 22,80,443,3306 192.0.2.50
```

**Output:**
```
╔══════════════════════════════════════════════════════════════════════╗
║ 🎯 SIMULATION MODE - No actual network traffic generated             ║
║ Simulating: NMAP                                                     ║
╚══════════════════════════════════════════════════════════════════════╝

Starting Nmap 7.93 ( https://nmap.org ) at 2025-12-09 14:30 UTC
SIMULATION MODE - No actual network traffic generated

Nmap scan report for 192.0.2.1 (192.0.2.45)
Host is up (0.082s latency).
PORT      STATE    SERVICE       VERSION
22/tcp    open     ssh           OpenSSH 8.2p1 Ubuntu
80/tcp    open     http          Apache httpd 2.4.41
443/tcp   open     ssl/http      nginx 1.18.0
3306/tcp  open     mysql         MySQL 5.7.38

Service detection performed. Please report any incorrect results at https://nmap.org/submit/
Nmap done: 1 IP address (1 host up) scanned in 8.42 seconds
```

### Example 2: Metasploit Exploitation Framework

```bash
python -m null_cli.cli use metasploit
```

**Interactive workflow simulation:**
```
msf6 > search eternalblue
msf6 > use exploit/windows/smb/ms17_010_eternalblue
msf6 exploit(windows/smb/ms17_010_eternalblue) > show options
msf6 exploit(windows/smb/ms17_010_eternalblue) > set RHOSTS 192.0.2.45
msf6 exploit(windows/smb/ms17_010_eternalblue) > exploit

[*] Started reverse TCP handler on 192.0.2.10:4444
[*] 192.0.2.45:445 - Target appears to be Windows 10 (Build 1809)
[+] 192.0.2.45:445 - Meterpreter session 1 opened

meterpreter > sysinfo
Computer        : DESKTOP-ABC123
OS              : Windows 10 (10.0 Build 17763)
```

### Example 3: Hydra Password Brute-Force

**SSH brute-force with wordlist:**
```bash
python -m null_cli.cli use hydra -l admin -P passwords.txt 192.0.2.1 ssh
```

**Multiple users and passwords:**
```bash
python -m null_cli.cli use hydra -L users.txt -P passwords.txt 192.0.2.1 ftp
```

**Output:**
```
Hydra v9.5 (c) 2023 by van Hauser/THC
⚠️  SIMULATION MODE - No actual authentication attempts

[DATA] attacking ssh://192.0.2.1:22/
[INFO] Testing 1 username(s) against 50 password(s)
[INFO] Using 16 threads

[STATUS] 12/50 attempts (24.0%) - 384.2 tries/sec
[STATUS] 25/50 attempts (50.0%) - 412.8 tries/sec
[STATUS] 38/50 attempts (76.0%) - 398.5 tries/sec

[22][SSH] host: 192.0.2.1   login: admin   password: Summer2024!
✅ SUCCESS: Valid credentials found

Attack Summary:
  Total attempts: 50
  Successful cracks: 1
  Time elapsed: 0.13 seconds
```

### Example 4: John the Ripper Hash Cracking

**Crack password hashes with wordlist:**
```bash
python -m null_cli.cli use john --wordlist=rockyou.txt hashes.txt
```

**Show previously cracked passwords:**
```bash
python -m null_cli.cli use john --show hashes.txt
```

**Incremental brute-force mode:**
```bash
python -m null_cli.cli use john --incremental hashes.txt
```

### Example 5: SQLmap SQL Injection

**Basic injection test:**
```bash
python -m null_cli.cli use sqlmap -u "http://example.com/page.php?id=1" --batch
```

**Enumerate databases:**
```bash
python -m null_cli.cli use sqlmap -u "http://example.com/page.php?id=1" --dbs --batch
```

**Dump specific table:**
```bash
python -m null_cli.cli use sqlmap -u "http://example.com/page.php?id=1" -D webapp_db -T users --dump --batch
```

**Output:**
```
sqlmap/1.7.2#stable (https://sqlmap.org)
⚠️  SIMULATION MODE - No actual SQL injection testing

[*] Testing URL: http://example.com/page.php?id=1
[*] Testing parameter: id

[*] Testing boolean-based blind SQL injection
✅ Parameter 'id' is vulnerable to boolean-based blind SQL injection

[*] Identifying backend DBMS
[+] Backend DBMS: MySQL 5.7.35

[*] Enumerating databases
[+] Available databases [5]:
    information_schema
    mysql
    webapp_db
    shop_db
    users_db
```

### Example 6: Nikto Web Scanner

```bash
python -m null_cli.cli use nikto -host example.com -port 443 -ssl
```

**Output:**
```
- Nikto v2.5.0
⚠️  SIMULATION MODE - No actual web requests

+ Target IP: 203.0.113.25
+ Target Hostname: example.com
+ Target Port: 443

[+] Server: nginx/1.18.0
+ OSVDB-3092: /admin/: Admin directory found
+ OSVDB-3233: /icons/README: Apache default file found
+ OSVDB-3268: /backup/: Directory indexing enabled
```

### Example 7: Gobuster Directory Enumeration

```bash
python -m null_cli.cli use gobuster dir -u http://example.com -w wordlist.txt -t 50
```

**With file extensions:**
```bash
python -m null_cli.cli use gobuster dir -u http://example.com -w wordlist.txt -x php,html,txt
```

### Example 8: WPScan WordPress Security

```bash
python -m null_cli.cli use wpscan --url https://example.com --enumerate u,vp
```

**With API token for vulnerability data:**
```bash
python -m null_cli.cli use wpscan --url https://example.com --enumerate vp --api-token YOUR_TOKEN
```

---

## 🎓 Educational Mode Deep Dive

### Enabling Educational Mode

**Globally (for all commands):**
```bash
python -m null_cli.cli config-cmd
# Select "Enable educational mode"
```

**Per-command basis:**
```bash
python -m null_cli.cli use nmap -sV 192.0.2.1 --educational
```

### What Educational Mode Teaches

**For each tool and flag combination, you'll learn:**

1. **Technical Explanation**
   - What the flag does technically
   - How it works under the hood
   - When to use it vs alternatives

2. **Practical Examples**
   - Real-world use cases
   - Flag combinations that work well together
   - Common mistakes to avoid

3. **Detection & Defense**
   - How defenders detect this activity
   - What logs are generated
   - How IDS/IPS/WAF responds

4. **Legal & Ethical Implications**
   - Laws that apply (CFAA, Computer Misuse Act)
   - Criminal vs civil consequences
   - When it's legal (authorized pentesting, bug bounties)

5. **Best Practices**
   - Industry-standard approaches
   - Stealth vs speed tradeoffs
   - Professional pentest methodology

### Example Educational Output

```bash
$ python -m null_cli.cli use nmap -A 192.0.2.1 --educational
```

```
╔════════════════════════════════════════════════════════════════════╗
║ 📚 Educational Mode                                                ║
╚════════════════════════════════════════════════════════════════════╝

Command: Nmap Network Scanner
What it does:
  -A (Aggressive Scan): Enables OS detection (-O), version detection 
  (-sV), script scanning (-sC), and traceroute. Comprehensive but noisy.
  
  Combines four powerful features:
  • OS Detection: TCP/IP fingerprinting identifies target operating system
  • Version Detection: Probes services to identify exact software versions
  • Script Scanning: Runs 100+ NSE scripts to test for vulnerabilities
  • Traceroute: Maps network path to target

  This is the most thorough scan but generates the most traffic and logs.

Key Flags Explained:
  -O (OS Detection): Requires root privileges and at least one open/closed
     port. Analyzes TCP/IP stack behavior to identify OS with ~95% accuracy.
     
  -sV (Version Detection): Sends protocol-specific probes to open ports.
     Can identify exact software versions including patch levels.
     
  -sC (Default Scripts): Runs safe, informative NSE scripts. Examples:
     • http-title: Grabs web page titles
     • ssh-hostkey: Shows SSH host keys
     • ssl-cert: Displays SSL certificate info
     
  -T<0-5> (Timing): Controls scan speed
     • T0=Paranoid: 5 min between probes (IDS evasion)
     • T3=Normal: Default balanced timing
     • T5=Insane: Parallel scanning, may crash targets

Real-world Impact:
  • Legal: Unauthorized port scanning is ILLEGAL in most jurisdictions.
    Can result in criminal charges under CFAA (US) or Computer Misuse Act (UK).
    
  • Detection: Modern IDS/IPS (Snort, Suricata) detect ALL scan types.
    Your source IP, timestamp, and scan pattern are logged.
    
  • Firewalls: Stateful firewalls rate-limit suspicious scans and may
    permanently blacklist your IP address.
    
  • Network Impact: Aggressive scans (-T4, -T5) can saturate small networks,
    causing denial of service. Always use -T2 or -T3 unless authorized.

Defenses:
  • Rate limiting at firewall level
  • Host-based firewalls (ufw, firewalld) drop suspicious packets
  • IDS/IPS with automated blocking (Fail2ban, OSSEC)
  • Network segmentation limits reconnaissance impact
  • Honeypots detect and track attackers

When It's Legal:
  ✅ Authorized penetration testing with written contract
  ✅ Bug bounty programs (within defined scope)
  ✅ Your own infrastructure and systems
  ✅ Lab environments (VirtualBox, VMware, cloud labs)
  ✅ Educational platforms (HackTheBox, TryHackMe)
```

---

## ⚙️ Configuration

### Configuration File Location

**Linux/macOS:**
```
~/.null-cli/config.json
```

**Windows:**
```
C:\Users\YourName\.null-cli\config.json
```

### Available Settings

```json
{
  "first_run": false,
  "favorite_tool": "nmap",
  "educational_mode": true,
  "paranoia_mode": false,
  "show_warnings": true,
  "log_commands": true
}
```

### Configuration Commands

```bash
# Interactive configuration menu
python -m null_cli.cli config-cmd

# View current configuration
cat ~/.null-cli/config.json

# Reset to defaults
python -m null_cli.cli reset
```

### Command History

History is stored in `~/.null-cli/history.json`:

```bash
# View recent commands
python -m null_cli.cli history

# View last 10 commands
python -m null_cli.cli history --limit 10

# Clear history
rm ~/.null-cli/history.json
```

---

## 🔒 Safety & Security

### How NULL-CLI Stays Safe

1. **No Network Operations**
   - All IP addresses use RFC 5737 test networks:
     - `192.0.2.0/24` (TEST-NET-1)
     - `198.51.100.0/24` (TEST-NET-2)
     - `203.0.113.0/24` (TEST-NET-3)
   - These ranges are reserved and will NEVER route to real systems

2. **No Filesystem Modifications**
   - Only writes to `~/.null-cli/` directory
   - Config and history files only
   - No system files touched
   - No malware or exploits

3. **Clear Simulation Markers**
   - Every output shows "⚠️ SIMULATION MODE" warning
   - Headers clearly state no real operations
   - Educational warnings throughout

4. **Educational Focus**
   - Explains legal consequences
   - Teaches ethical hacking principles
   - Encourages proper authorization

5. **Open Source**
   - All code visible on GitHub
   - Community-reviewed
   - No hidden functionality

### Paranoia Mode

Extra safety layer for cautious users:

```bash
# Enable paranoia mode
python -m null_cli.cli config-cmd
# Select "Enable paranoia mode"
```

With paranoia mode enabled:
- Confirmation required before simulating exploits
- Extra warnings for dangerous-sounding commands
- Double-check prompts for destructive flags

---

## 🤝 Contributing

We welcome contributions! Here's how you can help:

### Adding a New Tool

1. **Create simulator class:**

```python
# null_cli/simulators/your_tool.py
from .base import ToolSimulator
from ..ui import console

class YourToolSimulator(ToolSimulator):
    def __init__(self, educational: bool = False):
        super().__init__("your_tool", educational)
        
    def run(self, args: tuple):
        self._show_simulation_header()
        
        if self.educational:
            self._show_your_tool_education()
            
        # Simulation logic here
        self._simulate_your_tool(args)
```

2. **Add fake data generators:**

```python
# null_cli/data/generators.py
def generate_your_tool_data():
    return {
        'findings': [...],
        'stats': {...}
    }
```

3. **Register in CLI:**

```python
# null_cli/cli.py
from .simulators import YourToolSimulator

simulators = {
    'your_tool': YourToolSimulator,
    # ... other tools
}
```

4. **Update README** with tool info
5. **Submit pull request**

### Improving Existing Tools

- Add more command-line flags
- Enhance output realism
- Improve educational content
- Fix bugs or inconsistencies

### Code Style Guidelines

- Follow PEP 8
- Use type hints: `def func(arg: str) -> dict:`
- Add docstrings to all functions
- Keep functions under 50 lines
- Use meaningful variable names

### Testing

```bash
# Run basic tests
python -m null_cli.cli use nmap --help
python -m null_cli.cli use nmap -sV 192.0.2.1
python -m null_cli.cli use nmap -A -T4 192.0.2.1 --educational

# Test all tools
python -m null_cli.cli use metasploit
python -m null_cli.cli use hydra -l admin -P pass.txt 192.0.2.1 ssh
python -m null_cli.cli use john --show hashes.txt
python -m null_cli.cli use sqlmap -u "http://test.com?id=1" --dbs
python -m null_cli.cli use nikto -host test.com
python -m null_cli.cli use gobuster dir -u http://test.com -w list.txt
python -m null_cli.cli use wpscan --url http://test.com -e u
```

---

## 🐛 Troubleshooting

### Common Issues

**Issue: `ModuleNotFoundError: No module named 'null_cli'`**
```bash
# Solution: Ensure you're in the project directory and venv is activated
cd null-cli
source .venv/bin/activate  # Linux/macOS
# OR
.\.venv\Scripts\Activate.ps1  # Windows

# Reinstall
pip install -e .
```

**Issue: `Python not found` (Windows)**
```powershell
# Solution: Add Python to PATH
# 1. Search "Environment Variables" in Windows
# 2. Edit "Path" variable
# 3. Add: C:\Users\YourName\AppData\Local\Programs\Python\Python311
# 4. Restart terminal
```

**Issue: Permission denied on Linux**
```bash
# Solution: Don't use sudo with pip in venv
# Use virtual environment instead:
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
```

**Issue: `Execution Policy` error (Windows PowerShell)**
```powershell
# Solution: Allow script execution
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

**Issue: Colors not displaying correctly**
```bash
# Solution: Install Rich correctly
pip install --upgrade rich

# For Windows CMD (legacy), colors may not work
# Use PowerShell or Windows Terminal instead
```

### Getting Help

1. **Check existing issues**: [GitHub Issues](https://github.com/4fqr/null-cli/issues)
2. **Search documentation**: This README + code comments
3. **Open new issue**: Include OS, Python version, error message

---

## 📜 Legal Disclaimer

**NULL-CLI is for educational purposes only.**

This tool **DOES NOT perform any actual security operations**. All outputs are simulated using fake data and RFC 5737 test IP addresses. Understanding cybersecurity tools is essential for defenders and security professionals.

### Important Legal Points

✅ **NULL-CLI is completely legal to use** - It generates no network traffic and performs no real attacks.

❌ **Real security tools require authorization**:
- Written permission from system owners
- Proper penetration testing contracts
- Compliance with local laws (CFAA, Computer Misuse Act, etc.)
- Professional liability insurance for commercial pentesting

🎓 **Educational Use Cases (Legal)**:
- Learning security concepts in classrooms
- Practicing for security certifications (CEH, OSCP, etc.)
- Understanding tools before authorized pentesting
- Demonstrating tools in conferences/presentations
- Personal lab environments (VirtualBox, VMware, etc.)

⚖️ **Unauthorized Use is Illegal**:
- Port scanning without permission = Illegal
- Password brute-forcing systems = Felony
- SQL injection attacks = Computer Fraud and Abuse Act violation
- Network reconnaissance = Unauthorized access attempt

### Our Responsibility

We created NULL-CLI to:
- Make security education accessible
- Remove barriers for students without lab access
- Teach ethical hacking principles safely
- Demonstrate tool functionality without risk

We do NOT condone or support:
- Unauthorized access to computer systems
- Real attacks against systems you don't own
- Using knowledge for malicious purposes
- Violating computer crime laws

**Learn responsibly. Always get authorization. Stay ethical.**

---

## 📄 License

MIT License

Copyright (c) 2025 null-cli contributors

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

---

## 🙏 Acknowledgments

### Security Tools Simulated
- **Nmap** by Fyodor - The gold standard in network scanning
- **Metasploit Framework** by Rapid7 - Most comprehensive exploitation platform
- **Hydra** by van Hauser/THC - Fast network authentication cracker
- **John the Ripper** by Openwall - Legendary password cracker
- **SQLmap** by Bernardo Damele & Miroslav Stampar - Automated SQL injection tool
- **Nikto** by Chris Sullo - Web server scanner
- **Gobuster** by OJ Reeves - Fast directory/DNS brute-forcer  
- **WPScan** by WPScan Team - WordPress security scanner

### Libraries & Frameworks
- **Rich** by Will McGugan - Beautiful terminal formatting
- **Click** by Pallets - Elegant command-line interfaces
- **Faker** by Daniele Faraglia - Realistic fake data generation
- **Pyfiglet** by Peter Waller - ASCII art text

### Community
- **Kali Linux** - For providing the ultimate security toolkit
- **Offensive Security** - For OSCP certification and ethical hacking education
- **HackTheBox** & **TryHackMe** - For practical cybersecurity training platforms

---

## 📞 Contact & Support

- **GitHub Repository**: [https://github.com/4fqr/null-cli](https://github.com/4fqr/null-cli)
- **Issues & Bug Reports**: [GitHub Issues](https://github.com/4fqr/null-cli/issues)
- **Feature Requests**: [GitHub Discussions](https://github.com/4fqr/null-cli/discussions)
- **Security Vulnerabilities**: Open a private security advisory on GitHub

---

## 🗺️ Roadmap

### Planned Features
- [ ] More security tools (Aircrack-ng, Burp Suite, Wireshark simulation)
- [ ] Custom scenario builder (CTF-style challenges)
- [ ] Export simulation reports (PDF, HTML)
- [ ] Web interface (browser-based simulator)
- [ ] Interactive tutorials (guided learning paths)
- [ ] Certification exam prep mode (OSCP, CEH practice)

### In Progress
- [x] 8 core security tools implemented
- [x] Comprehensive educational mode
- [x] Cross-platform support
- [x] Beautiful terminal UI

---

<div align="center">

**Made with ❤️ for the cybersecurity learning community**

⭐ **Star this repo** if you find it useful!

🔗 **Share with students** learning security

🤝 **Contribute** to make it better

[⬆ Back to Top](#-null-cli)

</div>
