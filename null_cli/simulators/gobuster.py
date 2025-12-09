"""Gobuster directory/file brute-forcing simulator"""
import random
import time
from typing import Dict
from .base import ToolSimulator
from ..ui import console, print_error
from ..data.generators import generate_web_directories

class GobusterSimulator(ToolSimulator):
    def __init__(self, educational: bool = False):
        super().__init__("gobuster", educational)
    
    def run(self, args: tuple):
        self._show_simulation_header()
        
        if not args or '-h' in args or '--help' in args:
            self._show_help()
            return
        
        config = {'url': None, 'wordlist': None, 'mode': 'dir', 'extensions': [], 'threads': 10}
        
        i = 0
        while i < len(args):
            arg = args[i]
            if arg in ['-u', '--url'] and i + 1 < len(args):
                config['url'] = args[i + 1]
                i += 1
            elif arg in ['-w', '--wordlist'] and i + 1 < len(args):
                config['wordlist'] = args[i + 1]
                i += 1
            elif arg in ['-t', '--threads'] and i + 1 < len(args):
                config['threads'] = int(args[i + 1])
                i += 1
            elif arg in ['-x', '--extensions'] and i + 1 < len(args):
                config['extensions'] = args[i + 1].split(',')
                i += 1
            elif arg == 'dir':
                config['mode'] = 'dir'
            i += 1
        
        if not config['url']:
            print_error("No URL specified")
            return
        
        if self.educational:
            description = "[bold]Gobuster[/bold] - Fast directory/file brute-force tool written in Go. Multi-threaded and efficient.\n\n"
            description += "[bold cyan]Gobuster Modes:[/bold cyan]\n"
            description += "[bold]dir:[/bold] Directory/file enumeration (default mode)\n"
            description += "  • Discovers hidden directories: /admin, /backup, /api\n"
            description += "  • Finds exposed files: config.php, .env, database.sql\n"
            description += "[bold]dns:[/bold] Subdomain brute-forcing\n"
            description += "  • Finds subdomains: admin.site.com, api.site.com, dev.site.com\n"
            description += "[bold]vhost:[/bold] Virtual host discovery (same IP, different hostname)\n"
            description += "[bold]s3:[/bold] Amazon S3 bucket enumeration\n\n"
            description += "[bold cyan]Key Flags:[/bold cyan]\n"
            description += "[bold]-u/--url:[/bold] Target URL - Required for dir/vhost modes\n"
            description += "[bold]-w/--wordlist:[/bold] Path to wordlist file\n"
            description += "  • common.txt (4K entries), medium.txt (20K), big.txt (200K+)\n"
            description += "  • /usr/share/wordlists/dirbuster/ on Kali Linux\n"
            description += "  • SecLists: /Discovery/Web-Content/\n"
            description += f"[bold]-t/--threads {config['threads']}:[/bold] Concurrent connections. More = faster but riskier.\n"
            description += "  • 10 threads: Stealthy, 1-2 req/sec\n"
            description += "  • 50+ threads: Fast but obvious, triggers rate limits\n"
            description += "[bold]-x/--extensions:[/bold] File extensions to append\n"
            description += "  • -x php,txt,html,bak,old,zip\n"
            description += "  • Tests /admin.php, /admin.txt, /admin.html, etc\n"
            description += "[bold]-s/--status:[/bold] Positive status codes (default: 200,204,301,302,307,401,403)\n"
            description += "  • 200: Found, 301/302: Redirect, 401: Auth required, 403: Forbidden but exists\n"
            description += "[bold]-k:[/bold] Skip SSL certificate verification\n"
            description += "[bold]-e:[/bold] Print full URLs (not just paths)\n"
            description += "[bold]-r:[/bold] Follow redirects\n"
            description += "[bold]-n:[/bold] Don't print status codes\n"
            description += "[bold]-q:[/bold] Quiet mode (no banner)\n"
            description += "[bold]-o <file>:[/bold] Save output to file\n"
            description += "[bold]--delay:[/bold] Delay between requests (stealth)\n"
            description += "[bold]--useragent:[/bold] Custom User-Agent string\n"
            description += "[bold]--timeout:[/bold] HTTP request timeout\n\n"
            description += "[bold cyan]Wordlist Strategy:[/bold cyan]\n"
            description += "• Start with common.txt (fast)\n"
            description += "• If promising, escalate to medium.txt\n"
            description += "• Custom wordlists for app-specific paths (/api/v1/, /docs/)"
            
            impact = "[bold red]Real Gobuster Attacks:[/bold red]\n" \
                    "• [red]Massive Logs:[/red] Wordlist with 10K entries = 10K logged 404s. Forensically obvious.\n" \
                    "• [red]Bandwidth:[/red] 50 threads × 10K words = 500K requests. Can saturate small servers.\n" \
                    "• [yellow]WAF Detection:[/yellow] Cloudflare, ModSecurity detect rapid sequential 404s. Instant block.\n" \
                    "• [yellow]Rate Limiting:[/yellow] Most servers limit requests/IP. 429 Too Many Requests → IP ban.\n" \
                    "• [yellow]Reveals Infrastructure:[/yellow] Finding /admin exposes attack surface.\n" \
                    "• [red]Legal:[/red] Unauthorized directory enumeration = unauthorized access attempt. Criminal.\n\n" \
                    "[bold green]Defenses:[/bold green]\n" \
                    "• [green]Rate Limiting:[/green] fail2ban, nginx limit_req - block IPs exceeding threshold\n" \
                    "• [green]WAF:[/green] Detect sequential 404 patterns, block known wordlists\n" \
                    "• [green]Honeypots:[/green] Fake directories (/admin-secret/) that trigger alerts\n" \
                    "• [green]Remove Defaults:[/green] Delete unused directories, disable autoindex\n" \
                    "• [green]Authentication:[/green] Require login for sensitive directories\n" \
                    "• [green]Monitoring:[/green] Alert on >100 404s from single IP in 1 minute\n\n" \
                    "[bold cyan]Ethical Use:[/bold cyan] Bug bounties (within scope), your own servers, authorized pentests, CTF challenges.\n" \
                    "[bold cyan]Alternatives:[/bold cyan] ffuf (faster), dirb (older), feroxbuster (recursive), wfuzz (fuzzing)"
            
            self._show_educational_info("Gobuster Directory Brute-Force Tool", description, impact)
        
        self._log_simulation(' '.join(args))
        self._simulate_scan(config)
    
    def _simulate_scan(self, config: Dict):
        console.print("[bold cyan]Gobuster v3.6[/bold cyan]")
        console.print("[yellow]⚠️  SIMULATION MODE - No actual HTTP requests[/yellow]\n")
        
        console.print("[white]by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)[/white]\n")
        console.print(f"[cyan][+] Url:                  {config['url']}[/cyan]")
        console.print(f"[cyan][+] Method:               GET[/cyan]")
        console.print(f"[cyan][+] Threads:              {config['threads']}[/cyan]")
        console.print(f"[cyan][+] Wordlist:             {config['wordlist'] or 'default.txt'}[/cyan]")
        
        if config['extensions']:
            console.print(f"[cyan][+] Extensions:           {','.join(config['extensions'])}[/cyan]")
        
        console.print(f"[cyan][+] Status codes:         200,204,301,302,307,401,403[/cyan]")
        console.print(f"[dim][+] User Agent:          gobuster/3.6[/dim]\n")
        
        console.print("[cyan]===============================================================[/cyan]")
        console.print(f"[white]Starting gobuster in directory enumeration mode[/white]")
        console.print("[cyan]===============================================================[/cyan]\n")
        
        directories = generate_web_directories()
        
        for dir_info in directories:
            time.sleep(random.uniform(0.05, 0.15))
            status = dir_info['status']
            path = dir_info['path']
            size = dir_info['size']
            
            status_color = "green" if status == 200 else "yellow" if status in [301, 302] else "red"
            console.print(f"[{status_color}]{path:30}[/{status_color}] [white](Status: {status}) [Size: {size}][/white]")
        
        console.print(f"\n[cyan]===============================================================[/cyan]")
        console.print(f"[green]Finished[/green]")
        console.print("[cyan]===============================================================[/cyan]")
    
    def _show_help(self):
        console.print("""[bold cyan]Gobuster v3.6[/bold cyan]

Usage: gobuster [mode] [options]

[bold yellow]MODES:[/bold yellow]
  [cyan]dir[/cyan]      Directory/file brute-forcing mode

[bold yellow]OPTIONS:[/bold yellow]
  [cyan]-u, --url[/cyan]        Target URL
  [cyan]-w, --wordlist[/cyan]   Wordlist path
  [cyan]-t, --threads[/cyan]    Number of threads (default: 10)
  [cyan]-x, --extensions[/cyan] File extensions to search for

[bold green]Example:[/bold green] gobuster dir -u http://example.com -w wordlist.txt -x php,html

[bold red]SIMULATION MODE:[/bold red] No actual requests sent.
""")
