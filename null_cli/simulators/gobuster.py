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
            self._show_educational_info(
                "Gobuster Directory Brute-Forcing",
                "Gobuster uses wordlists to discover hidden directories and files on web servers. "
                "It's fast, threaded, and supports various modes (dir, dns, vhost, s3).\n\n"
                "Useful for finding admin panels, backup files, exposed directories.",
                "[bold red]Real Gobuster would:[/bold red]\n"
                "• Generate thousands of 404 errors in logs\n"
                "• Consume significant bandwidth\n"
                "• Trigger rate limiting and WAFs\n"
                "• Reveal hidden application structure\n"
                "• Be considered reconnaissance (requires permission)"
            )
        
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
