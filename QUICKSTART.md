# NULL-CLI Quick Start Guide

## Installation

```bash
# Clone the repository
git clone https://github.com/Daiwik-M-Jith/null-guard.git
cd null-guard

# Install in development mode
pip install -e .

# Or install from PyPI (when published)
pip install null-cli
```

## First Time Setup

Run null-cli without arguments for interactive setup:

```bash
python -m null_cli.cli
```

This will guide you through:
- Selecting your favorite tool
- Enabling educational mode
- Configuring safety preferences

## Quick Command Reference

### Nmap Simulations

```bash
# Basic port scan
python -m null_cli.cli use nmap scanme.nmap.org

# Service version detection
python -m null_cli.cli use nmap -sV -p 80,443 target.com

# Full scan with OS detection
python -m null_cli.cli use nmap -sS -O -p- target.com

# With educational mode
python -m null_cli.cli use nmap -sV target.com --educational
```

### Metasploit Simulations

```bash
# Start interactive msfconsole
python -m null_cli.cli use metasploit

# This will run through a predefined exploitation workflow showing:
# - Module search
# - Setting options
# - Running exploits
# - Managing sessions
```

### Configuration Commands

```bash
# View/change settings
python -m null_cli.cli config-cmd

# View command history
python -m null_cli.cli history

# See all supported tools
python -m null_cli.cli tools

# Reset to defaults
python -m null_cli.cli reset
```

## Educational Mode

Enable to see explanations of what real commands would do:

```bash
python -m null_cli.cli use nmap -sS target.com --educational
```

Educational mode shows:
- What the scan/exploit does technically
- Real-world legal and technical impact
- How defenders would detect it

## Safety Features

All simulations include:
- ✅ Clear "SIMULATION MODE" watermarks
- ✅ Zero actual network traffic
- ✅ Fake data from RFC 5737 test networks
- ✅ No filesystem changes (except ~/.null-cli/ config)
- ✅ Educational warnings about real-world consequences

## Paranoia Mode

Enable in config to require confirmation before every simulation:

```bash
python -m null_cli.cli config-cmd
# Select "Enable paranoia mode"
```

## Troubleshooting

### Command not found

If `null-cli` command doesn't work, use:
```bash
python -m null_cli.cli
```

### Import errors

Make sure all dependencies are installed:
```bash
pip install click rich pyfiglet faker
```

## Examples

### Learning nmap basics
```bash
# See all nmap options
python -m null_cli.cli use nmap --help

# Try a basic scan
python -m null_cli.cli use nmap -sV scanme.nmap.org

# Learn what -sS does
python -m null_cli.cli use nmap -sS target.com --educational
```

### Learning Metasploit workflow
```bash
# Start msfconsole
python -m null_cli.cli use metasploit

# Watch the automated workflow showing:
# 1. Searching for exploits
# 2. Selecting a module
# 3. Configuring options
# 4. Running the exploit
# 5. Managing sessions
```

## Configuration File Location

All config stored in: `~/.null-cli/`
- `config.json` - User preferences
- `history.log` - Command history

## Contributing

Want to add more tools? See CONTRIBUTING.md in the repository!

## Legal Reminder

This tool is for EDUCATION ONLY. Real penetration testing requires:
- Written authorization
- Proper training/certification
- Legal compliance
- Professional liability insurance

Unauthorized access is illegal. null-cli helps you learn safely!
