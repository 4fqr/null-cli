"""Hydra password cracking simulator - Simulates brute-force attacks safely"""
import random
import time
from typing import List, Dict, Optional

from .base import ToolSimulator
from ..ui import console, print_warning, print_error, print_success
from ..data.generators import (
    generate_fake_ip, generate_hostname, generate_username_list,
    generate_password_list, generate_hydra_attempt
)


class HydraSimulator(ToolSimulator):
    """Simulates THC-Hydra password cracking tool"""
    
    def __init__(self, educational: bool = False):
        super().__init__("hydra", educational)
        self.attempts = 0
        self.successful_cracks = []
        
    def run(self, args: tuple):
        """Execute hydra simulation"""
        self._show_simulation_header()
        
        # Handle help
        if not args or '-h' in args or '--help' in args:
            self._show_help()
            return
        
        # Parse arguments
        config = self._parse_arguments(list(args))
        
        if not config['target']:
            print_error("No target specified. Usage: hydra [options] target service")
            console.print("\n[cyan]Example:[/cyan] hydra -l admin -P passwords.txt 192.0.2.1 ssh")
            return
        
        # Educational mode
        if self.educational:
            self._show_hydra_education(config)
        
        # Log simulation
        self._log_simulation(' '.join(args))
        
        # Execute the attack simulation
        self._simulate_attack(config)
    
    def _parse_arguments(self, args: List[str]) -> Dict:
        """Parse hydra command line arguments"""
        config = {
            'target': None,
            'service': 'ssh',
            'port': None,
            'username': None,
            'username_list': None,
            'password': None,
            'password_list': None,
            'threads': 16,
            'verbose': False,
            'ssl': False,
            'timeout': 30,
        }
        
        i = 0
        while i < len(args):
            arg = args[i]
            
            if arg in ['-l', '-L'] and i + 1 < len(args):
                if arg == '-l':
                    config['username'] = args[i + 1]
                else:
                    config['username_list'] = args[i + 1]
                i += 1
            elif arg in ['-p', '-P'] and i + 1 < len(args):
                if arg == '-p':
                    config['password'] = args[i + 1]
                else:
                    config['password_list'] = args[i + 1]
                i += 1
            elif arg in ['-t', '-T'] and i + 1 < len(args):
                try:
                    config['threads'] = int(args[i + 1])
                except ValueError:
                    pass
                i += 1
            elif arg == '-s' and i + 1 < len(args):
                try:
                    config['port'] = int(args[i + 1])
                except ValueError:
                    pass
                i += 1
            elif arg in ['-v', '-V', '-d']:
                config['verbose'] = True
            elif arg == '-S':
                config['ssl'] = True
            elif arg == '-w' and i + 1 < len(args):
                try:
                    config['timeout'] = int(args[i + 1])
                except ValueError:
                    pass
                i += 1
            elif not arg.startswith('-'):
                # Target or service
                if not config['target']:
                    config['target'] = arg
                elif config['service'] == 'ssh':  # Default service, replace it
                    config['service'] = arg.lower()
            
            i += 1
        
        return config
    
    def _show_hydra_education(self, config: Dict):
        """Show educational information about Hydra attacks"""
        service = config['service'].upper()
        
        description = f"Hydra is a parallelized login cracker which supports numerous protocols. " \
                     f"It performs brute-force attacks against {service} authentication by trying " \
                     f"multiple username/password combinations rapidly.\n\n" \
                     f"[bold]How it works:[/bold]\n" \
                     f"• Sends login attempts to the {service} service\n" \
                     f"• Uses multiple threads ({config['threads']}) to parallelize attempts\n" \
                     f"• Analyzes responses to determine successful authentication\n" \
                     f"• Can test thousands of combinations per minute"
        
        impact = f"[bold red]Real Hydra attacks would:[/bold red]\n" \
                f"• Generate massive authentication logs on target system\n" \
                f"• Trigger account lockouts and security alerts\n" \
                f"• Consume significant network bandwidth\n" \
                f"• Cause service degradation or denial of service\n" \
                f"• Be detected by intrusion detection systems immediately\n" \
                f"• Result in IP blocking, firewall rules, and incident response\n" \
                f"• Constitute unauthorized access attempt (criminal offense)\n" \
                f"• Lead to immediate legal action and prosecution\n\n" \
                f"[bold yellow]Defense mechanisms:[/bold yellow]\n" \
                f"• Account lockout policies after N failed attempts\n" \
                f"• Rate limiting and connection throttling\n" \
                f"• Multi-factor authentication (MFA/2FA)\n" \
                f"• IP-based blocking and geo-filtering\n" \
                f"• CAPTCHA after failed attempts\n" \
                f"• Strong password policies"
        
        self._show_educational_info(
            f"Hydra Brute-Force Attack on {service}",
            description,
            impact
        )
    
    def _simulate_attack(self, config: Dict):
        """Simulate a Hydra password cracking attack"""
        target = config['target']
        service = config['service'].upper()
        port = config['port'] or self._get_default_port(service)
        
        # Print Hydra banner
        console.print(f"[bold cyan]Hydra v9.5 (c) 2023 by van Hauser/THC - Use allowed only for legal purposes[/bold cyan]")
        console.print(f"[yellow]⚠️  SIMULATION MODE - No actual authentication attempts[/yellow]\n")
        
        # Resolve target
        target_ip = generate_fake_ip()
        console.print(f"[cyan][DATA][/cyan] attacking {service.lower()}://{target}:{port}/")
        console.print(f"[cyan][INFO][/cyan] Resolved {target} to {target_ip}")
        
        # Prepare username and password lists
        usernames = []
        if config['username']:
            usernames = [config['username']]
        elif config['username_list']:
            console.print(f"[cyan][DATA][/cyan] Loading username list from {config['username_list']}")
            usernames = generate_username_list(random.randint(5, 15))
        else:
            usernames = ['admin']
        
        passwords = []
        if config['password']:
            passwords = [config['password']]
        elif config['password_list']:
            console.print(f"[cyan][DATA][/cyan] Loading password list from {config['password_list']}")
            passwords = generate_password_list(random.randint(10, 50))
        else:
            passwords = generate_password_list(10)
        
        total_attempts = len(usernames) * len(passwords)
        console.print(f"[cyan][INFO][/cyan] Testing {len(usernames)} username(s) against {len(passwords)} password(s) = {total_attempts} total attempts")
        console.print(f"[cyan][INFO][/cyan] Using {config['threads']} threads")
        console.print()
        
        # Simulate attack with realistic timing
        start_time = time.time()
        attempts_made = 0
        found_credentials = []
        
        # Simulate attempts
        for username in usernames:
            for password in passwords:
                attempts_made += 1
                
                # Simulate delay (faster with more threads)
                delay = random.uniform(0.01, 0.05) / config['threads']
                time.sleep(delay)
                
                # Small chance of success (realistic)
                if random.random() < 0.02:  # 2% success rate
                    found_credentials.append((username, password))
                    console.print(f"[green][{port}][{service}] host: {target_ip}   "
                                f"login: {username}   password: {password}[/green]")
                    print_success(f"Valid credentials found: {username}:{password}")
                else:
                    if config['verbose'] and attempts_made % 10 == 0:
                        console.print(f"[dim][{port}][{service}] host: {target_ip}   "
                                    f"login: {username}   password: {password}   (failed)[/dim]")
                
                # Show progress periodically
                if attempts_made % max(1, total_attempts // 5) == 0:
                    progress = (attempts_made / total_attempts) * 100
                    elapsed = time.time() - start_time
                    rate = attempts_made / elapsed if elapsed > 0 else 0
                    console.print(f"[cyan][STATUS][/cyan] {attempts_made}/{total_attempts} attempts "
                                f"({progress:.1f}%) - {rate:.1f} tries/sec")
        
        # Final statistics
        console.print()
        elapsed_time = time.time() - start_time
        rate = attempts_made / elapsed_time if elapsed_time > 0 else 0
        
        console.print(f"[bold white]Attack Summary:[/bold white]")
        console.print(f"[white]Total attempts: {attempts_made}[/white]")
        console.print(f"[white]Successful cracks: {len(found_credentials)}[/white]")
        console.print(f"[white]Time elapsed: {elapsed_time:.2f} seconds[/white]")
        console.print(f"[white]Average rate: {rate:.2f} attempts/second[/white]")
        
        if found_credentials:
            console.print(f"\n[bold green]✓ {len(found_credentials)} valid password(s) found:[/bold green]")
            for username, password in found_credentials:
                console.print(f"[green]  • {username}:{password}[/green]")
        else:
            console.print(f"\n[yellow]⚠️  No valid credentials found in this simulation[/yellow]")
        
        console.print(f"\n[dim]SIMULATION COMPLETE - No actual authentication attempts were made[/dim]")
    
    def _get_default_port(self, service: str) -> int:
        """Get default port for a service"""
        ports = {
            'SSH': 22,
            'FTP': 21,
            'TELNET': 23,
            'HTTP': 80,
            'HTTPS': 443,
            'SMB': 445,
            'RDP': 3389,
            'MYSQL': 3306,
            'POSTGRES': 5432,
            'VNC': 5900,
        }
        return ports.get(service.upper(), 22)
    
    def _show_help(self):
        """Display Hydra help information"""
        help_text = """
[bold cyan]Hydra v9.5 (c) 2023 by van Hauser/THC[/bold cyan]

Usage: hydra [options] target service

[bold yellow]TARGET OPTIONS:[/bold yellow]
  target can be IP address, hostname, or IP range

[bold yellow]LOGIN OPTIONS:[/bold yellow]
  [cyan]-l LOGIN[/cyan]         Single username to test
  [cyan]-L FILE[/cyan]          File containing list of usernames
  [cyan]-p PASS[/cyan]          Single password to test
  [cyan]-P FILE[/cyan]          File containing list of passwords

[bold yellow]TUNING OPTIONS:[/bold yellow]
  [cyan]-t TASKS[/cyan]         Number of parallel connections (default: 16)
  [cyan]-w TIME[/cyan]          Max wait time for responses (default: 30s)
  [cyan]-f[/cyan]               Exit after first found login/password pair
  [cyan]-s PORT[/cyan]          Custom port (instead of service default)
  [cyan]-S[/cyan]               Use SSL/TLS connection

[bold yellow]OUTPUT OPTIONS:[/bold yellow]
  [cyan]-v/-V[/cyan]            Verbose mode / Very verbose mode
  [cyan]-d[/cyan]               Debug mode
  [cyan]-o FILE[/cyan]          Write found login/password pairs to file

[bold yellow]SUPPORTED SERVICES:[/bold yellow]
  ssh, ftp, telnet, http, https, http-get, http-post,
  http-form-get, http-form-post, mysql, postgres, smb,
  rdp, vnc, pop3, imap, smtp, and many more

[bold green]EXAMPLES:[/bold green]
  hydra -l admin -P passwords.txt 192.0.2.1 ssh
  hydra -L users.txt -p password123 192.0.2.1 ftp
  hydra -l root -P /usr/share/wordlists/rockyou.txt target.com ssh -s 2222
  hydra -l admin -p admin 192.0.2.1 http-post-form "/login:username=^USER^&password=^PASS^:F=incorrect"

[bold red]SIMULATION MODE:[/bold red]
  This is a safe simulation - no actual brute-force attacks are performed.
  All results are generated using fake data. No systems are accessed.
  No passwords are actually tested. No authentication attempts are made.

[dim]For more information: https://github.com/vanhauser-thc/thc-hydra[/dim]
"""
        console.print(help_text)
