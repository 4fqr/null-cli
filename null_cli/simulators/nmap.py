"""Nmap network scanner simulator"""
import random
import re
from typing import List, Tuple

from .base import ToolSimulator
from ..ui import console, print_warning, print_error
from ..data.generators import (
    generate_fake_ip, generate_hostname, generate_open_ports,
    generate_os_detection, generate_mac_address, generate_network_traffic_stats
)


class NmapSimulator(ToolSimulator):
    """Simulates nmap network scanning tool"""
    
    def __init__(self, educational: bool = False):
        super().__init__("nmap", educational)
        
    def run(self, args: tuple):
        """Execute nmap simulation"""
        args_str = ' '.join(args)
        
        # Show simulation header
        self._show_simulation_header()
        
        # Handle help flag
        if '--help' in args or '-h' in args:
            self._show_help()
            return
            
        # Parse arguments
        scan_type = self._parse_scan_type(args)
        ports = self._parse_ports(args)
        targets = self._parse_targets(args)
        
        # Educational mode
        if self.educational:
            self._show_nmap_education(scan_type, ports, targets)
        
        # Warn about dangerous flags
        if '-oG' in args or '-oN' in args or '-oX' in args:
            print_warning("Output file flags detected - in real nmap, this would write to filesystem")
            console.print("[dim]SIMULATION: No files will be created[/dim]\n")
        
        # If no targets specified
        if not targets:
            print_error("No targets specified. Try: null-cli use nmap -sV scanme.nmap.org")
            return
        
        # Run simulation
        self._simulate_scan(scan_type, ports, targets, args)
        
    def _show_help(self):
        """Display nmap help information"""
        help_text = """
[bold cyan]Nmap 7.93 ( https://nmap.org )[/bold cyan]
Usage: nmap [Scan Type(s)] [Options] {target specification}

TARGET SPECIFICATION:
  Can pass hostnames, IP addresses, networks, etc.
  Ex: scanme.nmap.org, microsoft.com/24, 192.168.0.1; 10.0.0-255.1-254
  -iL <inputfilename>: Input from list of hosts/networks (SIMULATED)

SCAN TECHNIQUES:
  -sS/sT/sA/sW/sM: TCP SYN/Connect()/ACK/Window/Maimon scans
  -sU: UDP Scan
  -sN/sF/sX: TCP Null, FIN, and Xmas scans
  -sV: Probe open ports to determine service/version info

PORT SPECIFICATION:
  -p <port ranges>: Only scan specified ports
    Ex: -p22; -p1-65535; -p U:53,111,137,T:21-25,80,139,8080

SERVICE/VERSION DETECTION:
  -sV: Probe open ports to determine service/version info
  --version-intensity <level>: Set from 0 (light) to 9 (try all probes)

OS DETECTION:
  -O: Enable OS detection
  --osscan-limit: Limit OS detection to promising targets

TIMING AND PERFORMANCE:
  -T<0-5>: Set timing template (higher is faster)

OUTPUT:
  -oN/-oX/-oS/-oG <file>: Output scan in normal, XML, s|<rIpt kIddi3,
     and Grepable format (SIMULATED - no actual file writing)

[dim]SIMULATION MODE: This is a safe simulation - no actual network scanning occurs[/dim]
"""
        console.print(help_text)
        
    def _show_nmap_education(self, scan_type: str, ports: str, targets: List[str]):
        """Show educational information about nmap"""
        descriptions = {
            "sS": "TCP SYN scan sends SYN packets without completing TCP handshake - stealthy but requires root",
            "sT": "TCP Connect scan completes full TCP handshake - slower but works without privileges",
            "sU": "UDP scan for UDP services - slower than TCP scans",
            "sV": "Service version detection probes open ports to identify running services",
            "sA": "TCP ACK scan used to map firewall rulesets",
            "O": "OS detection uses TCP/IP stack fingerprinting to identify operating system",
        }
        
        scan_desc = descriptions.get(scan_type, "Basic port scan to discover open ports")
        
        impact = "Real nmap would send actual network packets to target hosts. This could:\n" \
                "  • Trigger IDS/IPS alerts\n" \
                "  • Be logged by firewalls\n" \
                "  • Be considered unauthorized port scanning (illegal without permission)\n" \
                "  • Impact network performance"
        
        self._show_educational_info(
            f"nmap -{scan_type} scan",
            scan_desc,
            impact
        )
        
    def _parse_scan_type(self, args: tuple) -> str:
        """Parse scan type from arguments"""
        scan_types = {
            '-sS': 'sS', '-sT': 'sT', '-sU': 'sU', '-sV': 'sV',
            '-sN': 'sN', '-sF': 'sF', '-sX': 'sX', '-sA': 'sA'
        }
        
        for arg in args:
            if arg in scan_types:
                return scan_types[arg]
        
        return 'sS'  # Default
        
    def _parse_ports(self, args: tuple) -> str:
        """Parse port specification from arguments"""
        for i, arg in enumerate(args):
            if arg == '-p' and i + 1 < len(args):
                return args[i + 1]
        
        # Check for common port shortcuts
        if '-F' in args:
            return "fast-100"
        if '--top-ports' in args:
            return "top-ports"
            
        return "1-1000"  # Default
        
    def _parse_targets(self, args: tuple) -> List[str]:
        """Parse target hosts from arguments"""
        # Filter out flags and their values
        targets = []
        skip_next = False
        
        flags_with_values = {'-p', '-T', '--min-rate', '--max-rate', '-iL', '-oN', '-oX', '-oG'}
        
        for i, arg in enumerate(args):
            if skip_next:
                skip_next = False
                continue
                
            if arg.startswith('-'):
                if arg in flags_with_values:
                    skip_next = True
                continue
                
            # This is a target
            targets.append(arg)
        
        return targets
        
    def _simulate_scan(self, scan_type: str, ports: str, targets: List[str], args: tuple):
        """Simulate the actual nmap scan"""
        # Header
        console.print(f"[green]Starting Nmap 7.93 ( https://nmap.org ) at {self._format_timestamp()}[/green]")
        console.print(f"[yellow]SIMULATION MODE - No actual network traffic generated[/yellow]\n")
        
        # Check for OS detection
        os_detect = '-O' in args
        service_detect = '-sV' in args or scan_type == 'sV'
        
        for target in targets:
            self._simulate_host_scan(target, scan_type, ports, os_detect, service_detect)
            console.print()
        
        # Summary
        stats = generate_network_traffic_stats()
        console.print(f"[green]Nmap done: {len(targets)} IP address(es) ({len(targets)} host(s) up) " \
                     f"scanned in {stats['duration']} seconds[/green]")
        
    def _simulate_host_scan(self, target: str, scan_type: str, ports: str,
                           os_detect: bool, service_detect: bool):
        """Simulate scanning a single host"""
        # Generate fake data
        target_ip = generate_fake_ip()
        hostname = target if '.' in target else generate_hostname()
        latency = round(random.uniform(0.001, 0.5), 3)
        
        console.print(f"[cyan]Nmap scan report for {hostname} ({target_ip})[/cyan]")
        console.print(f"[white]Host is up ({latency}s latency).[/white]")
        
        # Simulate port scanning delay
        self._simulate_delay(0.5, 1.5)
        
        # Port results
        open_ports = generate_open_ports()
        
        if not open_ports:
            console.print("[yellow]All scanned ports are filtered[/yellow]")
            return
        
        console.print(f"[white]Not shown: {random.randint(950, 990)} closed ports[/white]")
        console.print("[bold white]PORT      STATE    SERVICE       VERSION[/bold white]")
        
        for port_info in open_ports:
            port = port_info['port']
            state = port_info['state']
            service = port_info['service']
            version = port_info['version']
            
            # Color coding
            state_color = "green" if state == "open" else "yellow" if state == "filtered" else "red"
            
            if service_detect and version:
                console.print(f"[white]{port}/tcp[/white]   [{state_color}]{state:8}[/{state_color}] "
                            f"[cyan]{service:13}[/cyan] [dim]{version}[/dim]")
            else:
                console.print(f"[white]{port}/tcp[/white]   [{state_color}]{state:8}[/{state_color}] "
                            f"[cyan]{service}[/cyan]")
        
        # MAC Address (for local network scans)
        if random.choice([True, False]):
            mac = generate_mac_address()
            vendor = random.choice(["Intel Corporate", "VMware", "Cisco Systems", "Dell", "HP"])
            console.print(f"[white]MAC Address: {mac} ({vendor})[/white]")
        
        # OS Detection
        if os_detect:
            self._simulate_delay(0.3, 0.8)
            os_info = generate_os_detection()
            console.print(f"[white]OS details: {os_info['name']} (accuracy: {os_info['accuracy']})[/white]")
            console.print(f"[dim]Network Distance: {random.randint(1, 15)} hops[/dim]")
        
        # Service info footer
        if service_detect:
            console.print(f"[dim]Service detection performed. Please report any incorrect results at https://nmap.org/submit/[/dim]")


