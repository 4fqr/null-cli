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
[![Educational](https://img.shields.io/badge/purpose-educational-brightgreen.svg)](https://github.com/Daiwik-M-Jith/null-guard)

</div>

---

## 🌟 What is NULL-CLI?

**NULL-CLI** is a safe, educational simulation of popular Kali Linux security tools. It provides **100% realistic output** without performing any actual network operations or exploits. Perfect for:

- 🎓 **Students** learning cybersecurity concepts
- 👨‍🏫 **Educators** demonstrating security tools safely
- 🔬 **Researchers** prototyping security workflows
- 🧪 **Developers** testing security integrations without risk

> **No network traffic. No exploits. No legal risk. Just learning.**

---

## ✨ Features

- ✅ **100% Safe Simulation** - Zero network traffic, zero exploits, zero filesystem changes
- ✅ **Realistic Output** - Matches actual tool output with stunning terminal UI
- ✅ **Educational Mode** - Learn what real commands would do and their impact
- ✅ **Beginner-Friendly** - Interactive setup with command suggestions
- ✅ **Works Offline** - No API keys, no internet connection required
- ✅ **Beautiful Interface** - Rich terminal UI with colors and ASCII art
- ✅ **Command History** - Track your learning progress
- ✅ **Paranoia Mode** - Require confirmation before simulating exploits

---

## 🚀 Installation

### Stable Release (Recommended)

```bash
pip install null-cli
```

### Development Version

```bash
git clone https://github.com/4fqr/null-cli.git
cd null-cli
pip install -e .
```

### Requirements

- Python 3.9 or higher
- Works on Linux, macOS, and Windows

---

## 📖 Quick Start

### First Run Experience

Run null-cli using Python module syntax:

```bash
python -m null_cli.cli
```

You'll be greeted with a beautiful banner and guided through:
1. Selecting your favorite tool to simulate
2. Enabling educational mode (recommended for beginners)
3. Configuring safety preferences

### Simulating Tools

```bash
# Simulate nmap scan
python -m null_cli.cli use nmap -sV -p 80,443 scanme.nmap.org

# Simulate Metasploit exploit
python -m null_cli.cli use metasploit

# Enable educational mode for any command
python -m null_cli.cli use nmap -sS 192.0.2.1 --educational
```

---

## 🛠️ Supported Tools

| Tool | Category | Simulation Accuracy | Educational Mode | Status |
|------|----------|---------------------|------------------|--------|
| **nmap** | Network Scanner | ★★★★★ | ✅ Yes | ✅ Fully implemented |
| **metasploit** | Exploitation Framework | ★★★★★ | ✅ Yes | ✅ Fully implemented |
| **hydra** | Password Brute-Force | ★★★★★ | ✅ Yes | ✅ Fully implemented |
| **john** | Hash Cracking | ★★★★★ | ✅ Yes | ✅ Fully implemented |
| **sqlmap** | SQL Injection | ★★★★★ | ✅ Yes | ✅ Fully implemented |
| **nikto** | Web Vulnerability | ★★★★☆ | ✅ Yes | ✅ Fully implemented |
| **gobuster** | Directory Brute-Force | ★★★★★ | ✅ Yes | ✅ Fully implemented |
| **wpscan** | WordPress Scanner | ★★★★☆ | ✅ Yes | ✅ Fully implemented |

**8 tools fully implemented!** More coming soon. [Request a tool](https://github.com/4fqr/null-cli/issues) or contribute!

---

## 💡 Usage Examples

### Example 1: Nmap Port Scan

```bash
$ python -m null_cli.cli use nmap -sV -p 80,443 scanme.nmap.org
```

**Output:**
```
╔══════════════════════════════════════════════════════════════════════╗
║ 🎯 SIMULATION MODE - No actual network traffic or exploits generated ║
║ Simulating: NMAP                                                     ║
╚══════════════════════════════════════════════════════════════════════╝

Starting Nmap 7.93 ( https://nmap.org ) at 2025-12-07 14:32 UTC
SIMULATION MODE - No actual network traffic generated

Nmap scan report for scanme.nmap.org (198.51.100.45)
Host is up (0.124s latency).
Not shown: 987 closed ports
PORT      STATE    SERVICE       VERSION
80/tcp    open     http          Apache httpd 2.4.41
443/tcp   open     ssl/http      nginx 1.18.0

Service detection performed. Please report any incorrect results at https://nmap.org/submit/
Nmap done: 1 IP address (1 host up) scanned in 12.34 seconds
```

### Example 2: Metasploit Exploitation

```bash
$ python -m null_cli.cli use metasploit
```

**Output:**
```
                 ________________
              /                \
             /    SIMULATION     \
            /        MODE          \
           /      METASPLOIT        \
          /__________________________|

       =[ metasploit v6.3.4-dev                      ]
+ -- --=[ 2295 exploits - 1201 auxiliary - 409 post       ]
+ -- --=[ 968 payloads - 45 encoders - 11 nops            ]
+ -- --=[ 9 evasion                                       ]

⚠️  SIMULATION MODE - No actual exploits will be executed

msf6 > use exploit/windows/smb/ms17_010_eternalblue
msf6 exploit(windows/smb/ms17_010_eternalblue) > set RHOSTS 192.0.2.45
RHOSTS => 192.0.2.45
msf6 exploit(windows/smb/ms17_010_eternalblue) > exploit

[*] Started reverse TCP handler on 192.0.2.10:4444
[*] 192.0.2.45:445 - SIMULATION: Target appears to be Windows 10 (1809 - 21H1)
[*] 192.0.2.45:445 - SIMULATION: Sending stage (175174 bytes)
[+] 192.0.2.45:445 - SIMULATION: Meterpreter session 1 opened
```

### Example 3: Password Brute-Forcing with Hydra

```bash
$ python -m null_cli.cli use hydra -l admin -P passwords.txt 192.0.2.1 ssh
```

**Output includes:**
```
Hydra v9.5 (c) 2023 by van Hauser/THC
⚠️  SIMULATION MODE - No actual authentication attempts

[DATA] attacking ssh://192.0.2.1:22/
[INFO] Testing 1 username(s) against 25 password(s) = 25 total attempts

[22][SSH] host: 198.51.100.44   login: admin   password: password123
✅ SUCCESS: Valid credentials found: admin:password123

Attack Summary:
Total attempts: 25
Successful cracks: 1
```

### Example 4: SQL Injection Testing with SQLmap

```bash
$ python -m null_cli.cli use sqlmap -u "http://example.com/page?id=1" --dbs
```

**Output:**
```
sqlmap/1.7.2#stable (https://sqlmap.org)
⚠️  SIMULATION MODE - No actual SQL injection testing

[*] Testing for SQL injection vulnerabilities
✅ Parameter appears to be vulnerable to boolean-based blind injection

[+] Backend DBMS: MySQL 5.7.35
[+] Available databases [4]:
    information_schema
    mysql
    webapp_db
    users_db
```

### Example 5: Educational Mode

```bash
$ python -m null_cli.cli use nmap -sS 192.0.2.1 --educational
```

**Output includes:**
```
╔════════════════════════════════════════════════════════════════════╗
║ 📚 Educational Mode                                                ║
╚════════════════════════════════════════════════════════════════════╝

Command: TCP SYN Scan (Stealth Scan)
What it does: Sends TCP SYN packets to target ports without completing 
              the TCP handshake. Requires root privileges.

Technical: Uses raw sockets to craft SYN packets
Detection: Can be detected by IDS/IPS and firewall logs

Real-world impact:
  • Generate network traffic detected by security systems
  • Trigger IDS/IPS alerts and automated response
  • Be logged by firewalls and target systems
  • Considered unauthorized scanning (illegal without permission)
```

---

## 🎓 Educational Mode

Enable educational mode to learn what real commands would do:

```bash
# Enable globally in config
python -m null_cli.cli config-cmd

# Enable for a single command
python -m null_cli.cli use nmap -sV target.com --educational
```

Educational mode explains:
- **What the command does** - Technical explanation of the scan/exploit
- **Real-world impact** - Legal and technical consequences
- **Detection methods** - How defenders would spot this activity

---

## ⚙️ Configuration

### View/Change Settings

```bash
python -m null_cli.cli config-cmd
```

**Available settings:**
- **Educational Mode** - Show explanations for every command
- **Paranoia Mode** - Require confirmation before simulating
- **Favorite Tool** - Default tool to suggest

### Command History

```bash
# View recent simulations
python -m null_cli.cli history

# Limit results
python -m null_cli.cli history --limit 20
```

### Reset Configuration

```bash
python -m null_cli.cli reset
```

---

## 🔒 Safety Features

NULL-CLI is designed with multiple safety layers:

1. **Zero Network Operations** - All IP addresses use RFC 5737 test networks that don't route
2. **Zero Filesystem Changes** - Only writes to `~/.null-cli/` for config and history
3. **Clear Watermarks** - Every output clearly marked as SIMULATION MODE
4. **Educational Warnings** - Explains risks of real commands
5. **Paranoia Mode** - Optional confirmation before running commands

**Test networks used:**
- `192.0.2.0/24` (TEST-NET-1)
- `198.51.100.0/24` (TEST-NET-2)
- `203.0.113.0/24` (TEST-NET-3)

These are reserved IP ranges that will never route to real systems.

---

## 🤝 Contributing

We welcome contributions! Here's how you can help:

### Adding a New Tool Simulator

1. **Create simulator class** in `null_cli/simulators/your_tool.py`:

```python
from .base import ToolSimulator

class YourToolSimulator(ToolSimulator):
    def __init__(self, educational: bool = False):
        super().__init__("your_tool", educational)
        
    def run(self, args: tuple):
        self._show_simulation_header()
        # Your simulation logic here
```

2. **Add realistic fake data** to `null_cli/data/generators.py`
3. **Register in CLI** at `null_cli/cli.py`
4. **Add to supported tools table** in README

### Improving Simulations

- **More realistic output** - Compare with actual tool output
- **Additional flags** - Support more command-line options
- **Better fake data** - More realistic IPs, domains, vulnerabilities
- **Educational content** - Add explanations for commands

### Code Style

- Follow PEP 8
- Use type hints where possible
- Add docstrings to all functions
- Keep simulations in separate modules

---

## 📜 Legal Disclaimer

**NULL-CLI is for educational purposes only.**

This tool **does not perform any actual security operations**. All outputs are simulated using fake data. Understanding cybersecurity tools is essential for defenders, but actual penetration testing requires:

- ✅ **Written authorization** from system owners
- ✅ **Proper training and certification**
- ✅ **Compliance with local laws and regulations**
- ✅ **Professional liability insurance**

**Unauthorized access to computer systems is illegal** in most jurisdictions. NULL-CLI helps you learn safely without legal risk.

---

## 🐛 Bug Reports & Feature Requests

Found a bug or want a feature? [Open an issue](https://github.com/4fqr/null-cli/issues)!

Please include:
- Your OS and Python version
- Steps to reproduce
- Expected vs actual behavior
- Any error messages

---

## 📄 License

MIT License - See [LICENSE](LICENSE) file for details.

---

## 🙏 Acknowledgments

- **Nmap** - Network scanning tool by Fyodor
- **Metasploit** - Penetration testing framework by Rapid7
- **Kali Linux** - Security-focused Linux distribution
- **Rich** - Beautiful terminal formatting library
- **Click** - Command-line interface framework

---

## 📞 Contact

- **GitHub**: [@4fqr](https://github.com/4fqr)
- **Issues**: [GitHub Issues](https://github.com/4fqr/null-cli/issues)

---

<div align="center">

**Made with ❤️ for the cybersecurity learning community**

[⬆ Back to Top](#-null-cli)

</div>
