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
            description = "[bold]Nikto[/bold] - Open-source web server scanner with 6700+ vulnerability checks.\n\n"
            description += "[bold cyan]What Nikto Scans:[/bold cyan]\n"
            description += "[bold]Server Misconfigurations:[/bold]\n"
            description += "  • Default files (phpinfo.php, test.php, admin.html)\n"
            description += "  • Backup files (.bak, .old, ~, .swp)\n"
            description += "  • Exposed directories (.git, .svn, /admin, /backup)\n"
            description += "  • Directory listing enabled\n"
            description += "[bold]Outdated Software:[/bold]\n"
            description += "  • Apache 2.2.x vulnerabilities\n"
            description += "  • Old PHP versions with known exploits\n"
            description += "  • Vulnerable CMS versions (WordPress, Joomla)\n"
            description += "[bold]Security Headers:[/bold]\n"
            description += "  • Missing X-Frame-Options (clickjacking risk)\n"
            description += "  • No X-XSS-Protection\n"
            description += "  • Missing Content-Security-Policy\n"
            description += "  • HTTP Strict-Transport-Security absent\n"
            description += "[bold]Dangerous CGI/Scripts:[/bold]\n"
            description += "  • /cgi-bin/ scripts with known vulnerabilities\n"
            description += "  • Shell scripts, file upload forms\n\n"
            description += "[bold cyan]Key Nikto Flags:[/bold cyan]\n"
            description += f"[bold]-host:[/bold] Target hostname/IP - Required\n"
            description += f"[bold]-port {config['port']}:[/bold] Target port (80=HTTP, 443=HTTPS)\n"
            description += "[bold]-ssl:[/bold] Force SSL/TLS mode\n"
            description += "[bold]-Tuning X:[/bold] Scan categories:\n"
            description += "  • 1: Interesting files\n"
            description += "  • 2: Misconfiguration\n"
            description += "  • 3: Information disclosure\n"
            description += "  • 4: Injection (XSS/Script/HTML)\n"
            description += "  • 5: Remote file retrieval\n"
            description += "  • 6: Denial of Service\n"
            description += "  • 9: SQL injection\n"
            description += "  • x: Reverse tuning (exclude)\n"
            description += "[bold]-evasion:[/bold] IDS evasion techniques (random URI encoding, fake params)\n"
            description += "[bold]-Format:[/bold] Output: txt, html, csv, xml\n"
            description += "[bold]-useragent:[/bold] Custom User-Agent string\n"
            description += "[bold]-Display:[/bold] Output verbosity (1=errors, 2=cookies, 3=200 OK, 4=URLs, V=verbose)"
            
            impact = "[bold red]Real Nikto Scans:[/bold red]\n" \
                    "• [red]Extremely Noisy:[/red] Generates 1000s of requests in minutes. WAF instant detection.\n" \
                    "• [red]Logged Extensively:[/red] Every 404, every URL tried, your IP, User-Agent, timestamp.\n" \
                    "• [yellow]Triggers Alerts:[/yellow] IDS/IPS (Snort, Suricata) have Nikto signatures. Instant SOC notification.\n" \
                    "• [yellow]Slowness:[/yellow] Single-threaded by default. Full scan takes 10-30 minutes.\n" \
                    "• [yellow]False Positives:[/yellow] Reports many 'potential' vulnerabilities requiring manual verification.\n" \
                    "• [red]Legal:[/red] Unauthorized scanning = Computer Fraud and Abuse Act violation.\n\n" \
                    "[bold green]Defenses:[/bold green]\n" \
                    "• [green]WAF/ModSecurity:[/green] Blocks Nikto's signature User-Agent and scan patterns.\n" \
                    "• [green]Remove Defaults:[/green] Delete phpinfo.php, test files, default admin panels.\n" \
                    "• [green]Disable Directory Listing:[/green] Options -Indexes in Apache.\n" \
                    "• [green]Security Headers:[/green] Add X-Frame-Options, CSP, HSTS headers.\n" \
                    "• [green]Rate Limiting:[/green] Block IPs making 100+ requests/minute.\n" \
                    "• [green]Hide Server Version:[/green] ServerTokens Prod, Server: nginx (no version)\n\n" \
                    "[bold cyan]Better Alternatives:[/bold cyan] OWASP ZAP, Burp Suite (more thorough, less noisy), Acunetix (commercial).\n" \
                    "[bold cyan]Ethical Use:[/bold cyan] Bug bounties (with permission), your own servers, authorized pentests, CTF labs."
            
            self._show_educational_info("Nikto Web Vulnerability Scanner", description, impact)
        
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
