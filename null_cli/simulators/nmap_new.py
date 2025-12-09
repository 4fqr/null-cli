"""Enhanced Nmap network scanner simulator with accurate, varied outputs"""
import random
import re
import time
from typing import List, Tuple, Dict, Optional

from .base import ToolSimulator
from ..ui import console, print_warning, print_error, print_info
from ..data.generators import (
    generate_fake_ip, generate_hostname, generate_open_ports,
    generate_os_detection, generate_mac_address, generate_network_traffic_stats,
    generate_fake_ipv6
)


class NmapSimulator(ToolSimulator):
    """Simulates nmap network scanning tool with high accuracy"""
    
    def __init__(self, educational: bool = False):
        super().__init__("nmap", educational)
        self.scan_start_time = time.time()
        
    def run(self, args: tuple):
        """Execute nmap simulation with comprehensive flag support"""
        args_list = list(args)
        
        # Show simulation header
        self._show_simulation_header()
        
        # Handle help flag
        if '--help' in args or '-h' in args:
            self._show_help()
            return
        
        # Handle version flag
        if '--version' in args or '-V' in args:
            console.print("[bold cyan]Nmap version 7.94 ( https://nmap.org )[/bold cyan]")
            console.print("[dim]Platform: x86_64-pc-linux-gnu[/dim]")
            console.print("[dim]Compiled with: liblua-5.3.6 openssl-1.1.1n libpcap-1.10.1[/dim]")
            console.print("[yellow]⚠️  SIMULATION MODE - No actual scanning capability[/yellow]")
            return
            
        # Parse all arguments
        scan_config = self._parse_arguments(args_list)
        
        # Validate configuration
        if not scan_config['targets']:
            print_error("No targets specified. Usage: nmap [Scan Type] [Options] {target}")
            console.print("\n[cyan]Example:[/cyan] nmap -sV -p 80,443 scanme.nmap.org")
            console.print("[dim]Use --help for full documentation[/dim]\n")
            return
        
        # Educational mode with context-aware explanations
        if self.educational:
            self._show_contextual_education(scan_config)
        
        # Warn about file output flags
        if any(flag in args for flag in ['-oN', '-oX', '-oG', '-oA']):
            print_warning("Output file flags detected")
            console.print("[dim]SIMULATION: No files will be created[/dim]\n")
        
        # Log the simulation
        self._log_simulation(' '.join(args))
        
        # Execute the scan simulation
        self._simulate_scan(scan_config)
        
    def _parse_arguments(self, args: List[str]) -> Dict:
        """Parse nmap arguments into a configuration dictionary"""
        config = {
            'scan_type': 'sS',  # Default: SYN scan
            'port_range': None,
            'targets': [],
            'timing': 3,  # T3 is default
            'os_detection': False,
            'service_detection': False,
            'version_intensity': 7,
            'script_scan': False,
            'scripts': [],
            'aggressive': False,
            'ipv6': False,
            'udp': False,
            'traceroute': False,
            'reason': False,
            'packet_trace': False,
            'verbosity': 0,
            'top_ports': None,
            'all_ports': False,
            'fast_scan': False,
        }
        
        i = 0
        while i < len(args):
            arg = args[i]
            
            # Scan technique flags
            if arg in ['-sS', '-sT', '-sA', '-sW', '-sM', '-sU', '-sN', '-sF', '-sX', '-sY', '-sZ']:
                config['scan_type'] = arg[2:4] if len(arg) > 2 else arg[2]
                if arg == '-sU':
                    config['udp'] = True
            
            # Service/Version detection
            elif arg == '-sV':
                config['service_detection'] = True
            elif arg == '--version-intensity' and i + 1 < len(args):
                try:
                    config['version_intensity'] = int(args[i + 1])
                    i += 1
                except ValueError:
                    pass
            
            # OS detection
            elif arg == '-O':
                config['os_detection'] = True
            elif arg == '--osscan-guess':
                config['os_detection'] = True
            
            # Port specification
            elif arg == '-p' and i + 1 < len(args):
                config['port_range'] = args[i + 1]
                i += 1
            elif arg == '-F':
                config['fast_scan'] = True
            elif arg == '-p-':
                config['all_ports'] = True
            elif arg == '--top-ports' and i + 1 < len(args):
                try:
                    config['top_ports'] = int(args[i + 1])
                    i += 1
                except ValueError:
                    pass
            
            # Timing
            elif arg.startswith('-T') and len(arg) == 3:
                try:
                    config['timing'] = int(arg[2])
                except ValueError:
                    pass
            
            # Script scanning
            elif arg == '-sC':
                config['script_scan'] = True
            elif arg == '--script' and i + 1 < len(args):
                config['script_scan'] = True
                config['scripts'] = args[i + 1].split(',')
                i += 1
            
            # Aggressive scan
            elif arg == '-A':
                config['aggressive'] = True
                config['os_detection'] = True
                config['service_detection'] = True
                config['script_scan'] = True
                config['traceroute'] = True
            
            # IPv6
            elif arg == '-6':
                config['ipv6'] = True
            
            # Other options
            elif arg == '--traceroute':
                config['traceroute'] = True
            elif arg == '--reason':
                config['reason'] = True
            elif arg == '--packet-trace':
                config['packet_trace'] = True
            elif arg in ['-v', '-vv', '-vvv']:
                config['verbosity'] = len(arg) - 1
            elif arg == '-d':
                config['verbosity'] = 1
            
            # Skip known flags with values
            elif arg in ['-oN', '-oX', '-oG', '-oA', '-iL', '--min-rate', '--max-rate', 
                        '--min-hostgroup', '--max-hostgroup', '--host-timeout', '--scan-delay']:
                if i + 1 < len(args):
                    i += 1
            
            # Not a flag, must be a target
            elif not arg.startswith('-'):
                config['targets'].append(arg)
            
            i += 1
        
        return config
    
    def _show_contextual_education(self, config: Dict):
        """Show context-aware educational information based on scan configuration"""
        scan_type = config['scan_type']
        
        # Build comprehensive explanation based on actual flags used
        scan_descriptions = {
            'sS': {
                'name': 'TCP SYN Scan (Stealth Scan)',
                'description': 'Sends TCP SYN packets to target ports. If port responds with SYN/ACK, port is open. '
                              'Never completes the TCP handshake (no ACK sent back), making it stealthier than full connect scan. '
                              'Requires root/administrator privileges.',
                'technical': 'Uses raw sockets to craft SYN packets. Target responds: SYN/ACK = open, RST = closed, no response = filtered',
                'detection': 'Can be detected by IDS/IPS, firewall logs, and connection attempt monitoring'
            },
            'sT': {
                'name': 'TCP Connect Scan',
                'description': 'Performs complete TCP three-way handshake with target ports. '
                              'More reliable but slower and easier to detect. Does not require privileges.',
                'technical': 'Uses operating system connect() call. Completes full TCP handshake: SYN → SYN/ACK → ACK',
                'detection': 'Logged in target application logs, system logs, and connection monitoring tools'
            },
            'sU': {
                'name': 'UDP Scan',
                'description': 'Sends UDP packets to target ports. Much slower than TCP scans. '
                              'Open|filtered distinction is difficult - many UDP services don\'t respond to empty packets.',
                'technical': 'Sends UDP packets; ICMP Port Unreachable = closed, no response = open|filtered',
                'detection': 'Often goes undetected but can trigger rate limiting and ICMP alerts'
            },
            'sA': {
                'name': 'TCP ACK Scan',
                'description': 'Used to map firewall rulesets. Sends ACK packets to determine if ports are filtered. '
                              'Cannot determine if ports are open/closed, only filtered/unfiltered.',
                'technical': 'Sends ACK packets; RST response = unfiltered, no response = filtered',
                'detection': 'Can evade some stateless firewalls but detected by stateful inspection'
            },
            'sN': {
                'name': 'TCP NULL Scan',
                'description': 'Sends TCP packets with no flags set. Can evade some non-stateful firewalls. '
                              'RFC 793 compliant systems send RST for closed ports.',
                'technical': 'No flags set in TCP header. No response = open|filtered, RST = closed',
                'detection': 'Unusual packet pattern easily detected by modern IDS/IPS systems'
            },
            'sF': {
                'name': 'TCP FIN Scan',
                'description': 'Sends packets with only FIN flag. Similar to NULL scan, can evade some firewalls.',
                'technical': 'Only FIN flag set. No response = open|filtered, RST = closed',
                'detection': 'Anomalous FIN without prior connection triggers IDS alerts'
            },
            'sX': {
                'name': 'TCP Xmas Scan',
                'description': 'Sends packets with FIN, PSH, and URG flags (packet "lit up like a Christmas tree"). '
                              'Can evade some firewalls but very distinctive.',
                'technical': 'FIN, PSH, and URG flags set. No response = open|filtered, RST = closed',
                'detection': 'Highly unusual flag combination, easily detected and logged'
            },
            'sV': {
                'name': 'Service Version Detection',
                'description': 'Probes open ports to determine service type and version. '
                              'Sends various probes and analyzes responses.',
                'technical': 'Connects to open ports, sends probes, analyzes banners and responses',
                'detection': 'Creates actual connections, logged in service logs, generates more traffic'
            }
        }
        
        scan_info = scan_descriptions.get(scan_type, scan_descriptions['sS'])
        
        # Build impact description
        impacts = [
            "• Generate network traffic that can be detected by IDS/IPS systems",
            "• Trigger security alerts and automated response systems",
            "• Be logged by firewalls, routers, and target systems",
        ]
        
        if config['aggressive'] or config['service_detection']:
            impacts.append("• Create actual connections to services (logged in application logs)")
        
        if config['script_scan']:
            impacts.append("• Execute enumeration scripts that may trigger vulnerability scanners")
        
        if config['os_detection']:
            impacts.append("• Send unusual packets for OS fingerprinting (easily detected)")
        
        if config['timing'] >= 4:
            impacts.append("• Send rapid packets that may trigger rate limiting or DoS protections")
        
        impacts.extend([
            "• Be considered unauthorized scanning (illegal without permission)",
            "• Lead to IP blocking, account termination, or legal action"
        ])
        
        # Display educational information
        self._show_educational_info(
            scan_info['name'],
            f"{scan_info['description']}\n\n"
            f"[bold]Technical:[/bold] {scan_info['technical']}\n"
            f"[bold]Detection:[/bold] {scan_info['detection']}",
            "[bold red]Real-world Impact:[/bold red]\n" + "\n".join(impacts)
        )
    
    def _simulate_scan(self, config: Dict):
        """Execute the actual scan simulation with realistic output"""
        # Print scan start banner
        timing_name = ['Paranoid', 'Sneaky', 'Polite', 'Normal', 'Aggressive', 'Insane'][
            min(config['timing'], 5)]
        
        console.print(f"[green]Starting Nmap 7.94 ( https://nmap.org ) at {self._format_timestamp()}[/green]")
        console.print(f"[yellow]SIMULATION MODE - No actual network traffic generated[/yellow]")
        
        # Show scan parameters if verbose
        if config['verbosity'] > 0:
            console.print(f"[dim]Initiating {config['scan_type']} Scan[/dim]")
            console.print(f"[dim]Timing: {timing_name} ({config['timing']})[/dim]")
        
        console.print()
        
        # Simulate scan for each target
        for target in config['targets']:
            self._simulate_host_scan(target, config)
            console.print()
        
        # Print summary
        scan_duration = round(time.time() - self.scan_start_time + random.uniform(1.5, 8.5), 2)
        num_hosts = len(config['targets'])
        
        console.print(f"[green]Nmap done: {num_hosts} IP address(es) ({num_hosts} host(s) up) " 
                     f"scanned in {scan_duration} seconds[/green]")
    
    def _simulate_host_scan(self, target: str, config: Dict):
        """Simulate scanning a single host with all requested options"""
        # Generate or use target info
        if config['ipv6']:
            target_ip = generate_fake_ipv6()
        else:
            target_ip = generate_fake_ip()
        
        hostname = generate_hostname(target)
        
        # Vary latency based on timing template
        base_latency = [2.0, 1.0, 0.5, 0.15, 0.05, 0.01][config['timing']]
        latency = round(random.uniform(base_latency * 0.5, base_latency * 2), 3)
        
        # Print host header
        if hostname != target_ip:
            console.print(f"[cyan]Nmap scan report for {hostname} ({target_ip})[/cyan]")
        else:
            console.print(f"[cyan]Nmap scan report for {target_ip}[/cyan]")
        
        console.print(f"[white]Host is up ({latency}s latency).[/white]")
        
        # Simulate scanning delay based on timing
        if config['verbosity'] > 1:
            console.print(f"[dim]Scanning {target_ip} [/dim]")
        
        self._simulate_delay(0.3, 1.5 / (config['timing'] + 1))
        
        # Determine target OS hint for port generation
        os_hint = None
        if random.random() < 0.6:
            os_hint = random.choice(['windows', 'linux'])
        
        # Generate ports based on configuration
        open_ports = generate_open_ports(
            scan_type=config['scan_type'],
            port_range=config['port_range'],
            target_os=os_hint
        )
        
        if not open_ports:
            console.print("[yellow]All scanned ports are filtered[/yellow]")
            if config['reason']:
                console.print("[dim]Reason: no-response[/dim]")
            return
        
        # Determine number of not shown ports
        total_ports = 1000 if not config['all_ports'] else 65535
        if config['port_range']:
            if '-' in config['port_range']:
                start, end = map(int, config['port_range'].split('-'))
                total_ports = end - start + 1
            elif ',' in config['port_range']:
                total_ports = len(config['port_range'].split(','))
        
        not_shown = total_ports - len(open_ports)
        if not_shown > 0:
            state_type = "filtered" if config['scan_type'] in ['sA', 'sN', 'sF', 'sX'] else "closed"
            console.print(f"[white]Not shown: {not_shown} {state_type} ports[/white]")
        
        # Print port table header
        if config['reason']:
            console.print("[bold white]PORT      STATE    SERVICE       VERSION                    REASON[/bold white]")
        else:
            console.print("[bold white]PORT      STATE    SERVICE       VERSION[/bold white]")
        
        # Print each port
        for port_info in sorted(open_ports, key=lambda x: int(x['port'])):
            self._print_port_info(port_info, config)
        
        # MAC Address for local scans
        if random.choice([True, False]) and not config['ipv6']:
            mac = generate_mac_address()
            vendor = random.choice([
                "Intel Corporate", "VMware", "Cisco Systems", "Dell", 
                "HP", "Raspberry Pi Foundation", "ASUSTek Computer"
            ])
            console.print(f"[white]MAC Address: {mac} ({vendor})[/white]")
        
        # OS Detection
        if config['os_detection'] or config['aggressive']:
            self._simulate_delay(0.5, 1.2)
            console.print()
            
            os_info = generate_os_detection(hint=os_hint)
            
            if config['verbosity'] > 0:
                console.print("[bold white]OS detection:[/bold white]")
                console.print(f"[white]Running: {os_info['name']}[/white]")
                console.print(f"[white]OS CPE: {os_info['cpe']}[/white]")
                console.print(f"[white]OS details: {os_info['details']}[/white]")
                console.print(f"[dim]Aggressive OS guesses: {os_info['name']} ({os_info['accuracy']})[/dim]")
            else:
                console.print(f"[white]OS details: {os_info['name']}[/white]")
            
            hops = random.randint(1, 15)
            console.print(f"[dim]Network Distance: {hops} hop{'s' if hops != 1 else ''}[/dim]")
        
        # Script scanning results
        if config['script_scan'] or config['aggressive']:
            console.print()
            self._show_script_results(open_ports, config)
        
        # Traceroute
        if config['traceroute'] or config['aggressive']:
            console.print()
            self._show_traceroute(target_ip, target)
        
        # Service info footer
        if config['service_detection']:
            console.print(f"\n[dim]Service detection performed. Please report any incorrect results at https://nmap.org/submit/[/dim]")
    
    def _print_port_info(self, port_info: Dict, config: Dict):
        """Print a single port's information"""
        port = port_info['port']
        state = port_info['state']
        service = port_info['service']
        version = port_info.get('version', '')
        
        # Color coding
        state_color = "green" if state == "open" else "yellow" if state == "filtered" else "red"
        
        # Build port line
        port_str = f"[white]{port}/tcp[/white]"
        state_str = f"[{state_color}]{state:8}[/{state_color}]"
        service_str = f"[cyan]{service:13}[/cyan]"
        
        if config['service_detection'] and version:
            version_str = f"[dim]{version[:35]:35}[/dim]"
        else:
            version_str = ""
        
        # Add reason if requested
        if config['reason']:
            reasons = {
                'open': 'syn-ack',
                'closed': 'reset',
                'filtered': 'no-response',
                'open|filtered': 'no-response'
            }
            reason = reasons.get(state, 'unknown')
            reason_str = f"[dim]{reason}[/dim]"
            console.print(f"{port_str}   {state_str} {service_str} {version_str}  {reason_str}")
        else:
            if version_str:
                console.print(f"{port_str}   {state_str} {service_str} {version_str}")
            else:
                console.print(f"{port_str}   {state_str} {service_str}")
    
    def _show_script_results(self, open_ports: List[Dict], config: Dict):
        """Show NSE script scan results"""
        console.print("[bold white]Host script results:[/bold white]")
        
        # Show some realistic script results
        scripts_run = config['scripts'] if config['scripts'] else ['default']
        
        # SMB scripts
        if any(p['port'] == '445' for p in open_ports):
            console.print("[white]| smb2-security-mode:[/white]")
            console.print("[white]|   3:1:1:[/white]")
            console.print("[white]|_    Message signing enabled but not required[/white]")
        
        # HTTP scripts
        if any(p['port'] in ['80', '443', '8080'] for p in open_ports):
            console.print("[white]| http-title:[/white]")
            titles = ["Welcome", "Home Page", "Index of /", "Apache2 Ubuntu Default Page"]
            console.print(f"[white]|_  {random.choice(titles)}[/white]")
        
        # SSH scripts
        if any(p['port'] == '22' for p in open_ports):
            console.print("[white]| ssh-hostkey:[/white]")
            console.print("[white]|   2048 aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:66:77:88:99 (RSA)[/white]")
            console.print("[white]|_  256 ab:cd:ef:01:23:45:67:89:ab:cd:ef:01:23:45:67:89 (ECDSA)[/white]")
    
    def _show_traceroute(self, target_ip: str, target: str):
        """Show traceroute output"""
        console.print("[bold white]TRACEROUTE[/bold white]")
        
        hops = random.randint(3, 12)
        
        for hop in range(1, hops + 1):
            if hop == hops:
                # Final hop is target
                latency = round(random.uniform(1, 50), 2)
                console.print(f"[white]{hop:2}  {latency:6.2f} ms {target_ip}[/white]")
            else:
                latency = round(random.uniform(1, 30) * hop, 2)
                hop_ip = generate_fake_ip()
                
                # Sometimes show hostname
                if random.random() < 0.3:
                    hop_host = f"router{hop}.isp.net"
                    console.print(f"[dim]{hop:2}  {latency:6.2f} ms {hop_host} ({hop_ip})[/dim]")
                else:
                    console.print(f"[dim]{hop:2}  {latency:6.2f} ms {hop_ip}[/dim]")
    
    def _show_help(self):
        """Display comprehensive nmap help information"""
        help_text = """
[bold cyan]Nmap 7.94 ( https://nmap.org )[/bold cyan]
Usage: nmap [Scan Type(s)] [Options] {target specification}

[bold yellow]TARGET SPECIFICATION:[/bold yellow]
  Can pass hostnames, IP addresses, networks, etc.
  Ex: scanme.nmap.org, microsoft.com/24, 192.168.0.1; 10.0.0-255.1-254
  [cyan]-iL <inputfilename>[/cyan]: Input from list of hosts/networks (simulated)
  [cyan]-6[/cyan]: Enable IPv6 scanning

[bold yellow]SCAN TECHNIQUES:[/bold yellow]
  [cyan]-sS[/cyan]: TCP SYN scan (default, requires root)
  [cyan]-sT[/cyan]: TCP Connect() scan (default for non-root)
  [cyan]-sA[/cyan]: TCP ACK scan (for firewall rule mapping)
  [cyan]-sW[/cyan]: TCP Window scan
  [cyan]-sM[/cyan]: TCP Maimon scan
  [cyan]-sU[/cyan]: UDP Scan
  [cyan]-sN/-sF/-sX[/cyan]: TCP Null, FIN, and Xmas scans
  [cyan]-sV[/cyan]: Probe open ports to determine service/version info

[bold yellow]PORT SPECIFICATION:[/bold yellow]
  [cyan]-p <port ranges>[/cyan]: Only scan specified ports
    Ex: -p22; -p1-65535; -p U:53,111,137,T:21-25,80,139,8080
  [cyan]-p-[/cyan]: All 65535 ports
  [cyan]-F[/cyan]: Fast mode - Scan fewer ports than default
  [cyan]--top-ports <number>[/cyan]: Scan N most common ports

[bold yellow]SERVICE/VERSION DETECTION:[/bold yellow]
  [cyan]-sV[/cyan]: Probe open ports to determine service/version info
  [cyan]--version-intensity <level>[/cyan]: Set from 0 (light) to 9 (try all probes)
  [cyan]--version-light[/cyan]: Limit to most likely probes (intensity 2)
  [cyan]--version-all[/cyan]: Try every single probe (intensity 9)

[bold yellow]OS DETECTION:[/bold yellow]
  [cyan]-O[/cyan]: Enable OS detection
  [cyan]--osscan-limit[/cyan]: Limit OS detection to promising targets
  [cyan]--osscan-guess[/cyan]: Guess OS more aggressively

[bold yellow]SCRIPT SCAN:[/bold yellow]
  [cyan]-sC[/cyan]: Equivalent to --script=default
  [cyan]--script=<script name>[/cyan]: Run specific NSE scripts

[bold yellow]TIMING AND PERFORMANCE:[/bold yellow]
  [cyan]-T<0-5>[/cyan]: Set timing template (higher is faster)
    -T0: Paranoid   -T1: Sneaky   -T2: Polite
    -T3: Normal     -T4: Aggressive -T5: Insane

[bold yellow]OUTPUT:[/bold yellow]
  [cyan]-oN/-oX/-oG <file>[/cyan]: Output scan in normal, XML, or Grepable format
  [cyan]-oA <basename>[/cyan]: Output in all formats
  [cyan]-v[/cyan]: Increase verbosity level (use -vv or more for greater effect)
  [cyan]-d[/cyan]: Increase debugging level

[bold yellow]MISC OPTIONS:[/bold yellow]
  [cyan]-A[/cyan]: Enable OS detection, version detection, script scanning, traceroute
  [cyan]--reason[/cyan]: Display reason for port state
  [cyan]--packet-trace[/cyan]: Show all packets sent and received
  [cyan]--traceroute[/cyan]: Trace hop path to each host
  [cyan]-6[/cyan]: Enable IPv6 scanning
  [cyan]-h, --help[/cyan]: Display this help
  [cyan]-V, --version[/cyan]: Print version number

[bold red]SIMULATION MODE:[/bold red]
  This is a safe simulation - no actual network scanning occurs.
  All output is generated using fake data from RFC 5737 test networks.
  No packets are sent, no systems are accessed, no logs are created.

[bold green]EXAMPLES:[/bold green]
  nmap -sV -p 80,443 scanme.nmap.org
  nmap -sS -O -T4 192.0.2.0/24
  nmap -A -v target.com
  nmap -sU -p 53,111,137 192.0.2.1

[dim]For more information: https://nmap.org/book/man.html[/dim]
"""
        console.print(help_text)
