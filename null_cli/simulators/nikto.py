"""Nikto web server scanner simulator"""
import random
import time
from typing import Dict
from .base import ToolSimulator
from ..ui import console, print_error
from ..data.generators import generate_hostname, generate_nikto_findings, generate_fake_ip

class NiktoSimulator(ToolSimulator):
    def __init__(self, educational: bool = False):
        super().__init__("nikto", educational)
    
    def run(self, args: tuple):
        self._show_simulation_header()
        
        if not args or '-h' in args or '-H' in args:
            self._show_help()
            return
        
        config = {'host': None, 'port': 80, 'ssl': False}
        
        for i, arg in enumerate(args):
            if arg in ['-h', '-host'] and i + 1 < len(args):
                config['host'] = args[i + 1]
            elif arg in ['-p', '-port'] and i + 1 < len(args):
                config['port'] = int(args[i + 1])
            elif arg in ['-ssl', '-SSL']:
                config['ssl'] = True
        
        if not config['host']:
            print_error("No host specified")
            return
        
        if self.educational:
            self._show_educational_info(
                "Nikto Web Server Scanner",
                "Nikto scans web servers for known vulnerabilities, misconfigurations, "
                "dangerous files/CGIs, outdated server software, and security issues. "
                "It checks against a database of 6700+ items.",
                "[bold red]Real Nikto scans would:[/bold red]\n"
                "• Generate extensive web server logs\n"
                "• Trigger Web Application Firewalls (WAFs)\n"
                "• Be detected by intrusion detection systems\n"
                "• May cause false positives in vulnerability scanners\n"
                "• Require authorization from system owner"
            )
        
        self._log_simulation(' '.join(args))
        self._simulate_scan(config)
    
    def _simulate_scan(self, config: Dict):
        console.print("[bold cyan]- Nikto v2.5.0[/bold cyan]")
        console.print("[yellow]⚠️  SIMULATION MODE - No actual web requests[/yellow]\n")
        
        protocol = "https" if config['ssl'] else "http"
        console.print(f"[cyan]+ Target IP: {generate_fake_ip()}[/cyan]")
        console.print(f"[cyan]+ Target Hostname: {config['host']}[/cyan]")
        console.print(f"[cyan]+ Target Port: {config['port']}[/cyan]")
        console.print(f"[cyan]+ Start Time: {self._format_timestamp()}[/cyan]\n")
        
        console.print(f"[white]+ Server: {random.choice(['Apache/2.4.41', 'nginx/1.18.0', 'Microsoft-IIS/10.0'])}[/white]")
        console.print(f"[dim]+ The anti-clickjacking X-Frame-Options header is not present.[/dim]\n")
        
        # Simulate scanning
        for _ in range(random.randint(3, 6)):
            time.sleep(random.uniform(0.2, 0.5))
            console.print(f"[dim]+ OSVDB-{random.randint(1000, 9999)}: Scanning...[/dim]")
        
        console.print()
        findings = generate_nikto_findings()
        
        for finding in findings:
            severity_color = {"critical": "red", "warning": "yellow", "info": "cyan"}[finding["severity"]]
            console.print(f"[{severity_color}]+ OSVDB-{finding['id']}: {finding['message']}[/{severity_color}]")
        
        console.print(f"\n[green]+ {len(findings)} item(s) reported on remote host[/green]")
        console.print(f"[dim]+ End Time: {self._format_timestamp()}[/dim]")
    
    def _show_help(self):
        console.print("""[bold cyan]Nikto v2.5.0[/bold cyan]
Usage: nikto [options]

[cyan]-host[/cyan]     Target host
[cyan]-port[/cyan]     Port (default: 80)
[cyan]-ssl[/cyan]      Force SSL mode

[bold green]Example:[/bold green] nikto -host example.com -port 443 -ssl

[bold red]SIMULATION MODE:[/bold red] No actual scanning performed.
""")
