"""John the Ripper password hash cracking simulator"""
import random
import time
from typing import List, Dict

from .base import ToolSimulator
from ..ui import console, print_error, print_success
from ..data.generators import generate_password_hash, generate_hash_crack_session


class JohnSimulator(ToolSimulator):
    """Simulates John the Ripper password cracker"""
    
    def __init__(self, educational: bool = False):
        super().__init__("john", educational)
    
    def run(self, args: tuple):
        """Execute john simulation"""
        self._show_simulation_header()
        
        if not args or '--help' in args:
            self._show_help()
            return
        
        config = self._parse_arguments(list(args))
        
        if self.educational:
            self._show_john_education(config)
        
        self._log_simulation(' '.join(args))
        self._simulate_cracking(config)
    
    def _parse_arguments(self, args: List[str]) -> Dict:
        """Parse john arguments"""
        config = {
            'hash_file': None,
            'wordlist': None,
            'format': None,
            'show': False,
            'incremental': False,
            'rules': False,
            'single': False,
        }
        
        for i, arg in enumerate(args):
            if arg == '--wordlist' and i + 1 < len(args):
                config['wordlist'] = args[i + 1]
            elif arg == '--format' and i + 1 < len(args):
                config['format'] = args[i + 1]
            elif arg == '--show':
                config['show'] = True
            elif arg == '--incremental':
                config['incremental'] = True
            elif arg == '--rules':
                config['rules'] = True
            elif arg == '--single':
                config['single'] = True
            elif not arg.startswith('-') and not config['hash_file']:
                config['hash_file'] = arg
        
        return config
    
    def _show_john_education(self, config: Dict):
        """Educational information about John the Ripper"""
        description_parts = []
        
        description_parts.append("[bold]John the Ripper[/bold] - Fast password cracker supporting 400+ hash types and multiple attack modes.\n\n")
        
        # Attack modes based on config
        description_parts.append("[bold cyan]Attack Modes:[/bold cyan]")
        
        if config['wordlist']:
            description_parts.append("\n[bold]--wordlist (Dictionary Attack):[/bold] Tests passwords from file line-by-line. Fast and effective.")
            description_parts.append("\n  • [cyan]rockyou.txt:[/cyan] 14M passwords from breaches. Cracks 30-40% of weak hashes.")
            description_parts.append("\n  • [cyan]Custom wordlists:[/cyan] Company names, dates, common phrases.")
            description_parts.append("\n  • [cyan]Speed:[/cyan] Millions of passwords/sec for fast hashes (MD5), thousands/sec for slow (bcrypt).")
        
        if config['rules']:
            description_parts.append("\n[bold]--rules:[/bold] Apply mutations to wordlist entries. Dramatically increases effectiveness.")
            description_parts.append("\n  • Append numbers: password → password123")
            description_parts.append("\n  • Capitalize: password → Password, PASSWORD")
            description_parts.append("\n  • L33t speak: password → p@ssw0rd")
            description_parts.append("\n  • Common patterns: password → password!, Password1")
        
        if config['incremental']:
            description_parts.append("\n[bold]--incremental (Brute-Force):[/bold] Tries all possible character combinations.")
            description_parts.append("\n  • Extremely thorough but SLOW. Starts with 'a', ends with 'zzzzzzzzz...'")
            description_parts.append("\n  • 8-char password (lowercase+numbers): ~36^8 = 2.8 trillion combinations")
            description_parts.append("\n  • At 1M/sec: 32 days. At 1B/sec (GPU): 46 minutes.")
        
        if config['single']:
            description_parts.append("\n[bold]--single:[/bold] Uses username/GECOS info from passwd file.")
            description_parts.append("\n  • Fast pre-attack. Finds users who use their username as password.")
            description_parts.append("\n  • Tries username, reversed, with numbers, capitalized.")
        
        if config['show']:
            description_parts.append("\n[bold]--show:[/bold] Display previously cracked passwords from john.pot file.")
        
        # Hash formats
        description_parts.append("\n\n[bold]--format <type>:[/bold] Specify hash algorithm:")
        description_parts.append("\n  • [cyan]md5/md5crypt:[/cyan] Old Unix. Very fast - billions/sec with GPU.")
        description_parts.append("\n  • [cyan]sha256/sha512:[/cyan] Modern Unix/Linux. Faster than md5crypt.")
        description_parts.append("\n  • [cyan]bcrypt:[/cyan] Designed to be slow. ~1000-10000 hashes/sec. Strong defense.")
        description_parts.append("\n  • [cyan]NT (NTLM):[/cyan] Windows hashes. Fast to crack. Common target.")
        description_parts.append("\n  • [cyan]Raw-MD5/SHA1:[/cyan] Unsalted. Pre-computed rainbow tables exist.")
        description_parts.append("\n  • [cyan]descrypt:[/cyan] Ancient DES-based Unix. Trivially crackable.")
        
        description_parts.append("\n\n[bold cyan]Additional Options:[/bold cyan]")
        description_parts.append("\n[bold]--fork=N:[/bold] Multi-processing across N CPU cores.")
        description_parts.append("\n[bold]--session=NAME:[/bold] Save/restore session. Resume interrupted cracks.")
        description_parts.append("\n[bold]--pot=FILE:[/bold] Custom cracked password storage file.")
        
        full_description = ''.join(description_parts)
        
        impact = "[bold red]Real John the Ripper Attacks:[/bold red]\n" \
                "• [red]Require Stolen Hashes:[/red] Must extract from /etc/shadow, SAM file, database dump. Usually requires prior breach.\n" \
                "• [red]Massive Resource Consumption:[/red] Maxes out CPU/GPU for hours/days/weeks. Electricity costs can exceed $100s.\n" \
                "• [red]Success Rate Varies:[/red]\n" \
                "  - Weak passwords (password123, qwerty): Minutes\n" \
                "  - Common passwords with rules: Hours to days\n" \
                "  - Strong passwords (14+ random chars): Months to never\n" \
                "  - Bcrypt/Argon2 with strong password: Practically uncrackable\n" \
                "• [yellow]Legal Status:[/yellow] Possessing stolen hashes = crime. Cracking without authorization = unauthorized access.\n\n" \
                "[bold green]Defenses:[/bold green]\n" \
                "• [green]Strong Passwords:[/green] 14+ characters, random, unique per site. Use password manager.\n" \
                "• [green]Modern Hash Algorithms:[/green] bcrypt, scrypt, Argon2 with high cost factor. Avoid MD5, SHA1, plain SHA256.\n" \
                "• [green]Salting:[/green] Unique salt per password prevents rainbow table attacks.\n" \
                "• [green]Multi-Factor Auth (MFA):[/green] Even if password cracked, can't login without 2nd factor.\n" \
                "• [green]Monitoring:[/green] Detect hash file access, unusual CPU spikes.\n\n" \
                "[bold cyan]Legitimate Uses:[/bold cyan] Password audits (authorized), forensics, your own hash cracking, CTFs."
        
        self._show_educational_info("John the Ripper Password Cracker", full_description, impact)
    
    def _simulate_cracking(self, config: Dict):
        """Simulate password cracking"""
        console.print("[bold cyan]John the Ripper 1.9.0-jumbo-1 (Bleeding-Jumbo)[/bold cyan]")
        console.print("[yellow]⚠️  SIMULATION MODE - No actual hash cracking[/yellow]\n")
        
        if config['show']:
            self._show_cracked_passwords()
            return
        
        if not config['hash_file']:
            print_error("No hash file specified")
            console.print("\n[cyan]Usage:[/cyan] john --wordlist=passwords.txt hashes.txt")
            return
        
        # Simulate loading hashes
        console.print(f"[cyan]Loaded {random.randint(1, 10)} password hash(es) from {config['hash_file']}[/cyan]")
        
        hash_type = config['format'] or random.choice(['MD5', 'SHA256', 'NTLM', 'bcrypt'])
        console.print(f"[cyan]Detected hash type: {hash_type}[/cyan]\n")
        
        mode = "wordlist" if config['wordlist'] else "incremental" if config['incremental'] else "single"
        
        if config['wordlist']:
            console.print(f"[cyan]Using wordlist: {config['wordlist']}[/cyan]")
            num_words = random.randint(1000, 1000000)
            console.print(f"[dim]Loaded {num_words} words[/dim]\n")
        
        # Simulate cracking process
        console.print(f"[bold white]Proceeding with {mode} crack mode[/bold white]")
        console.print("[dim]Press Ctrl-C to abort (simulated)[/dim]\n")
        
        start_time = time.time()
        cracked = []
        
        # Simulate some attempts
        for i in range(random.randint(3, 7)):
            time.sleep(random.uniform(0.3, 0.8))
            
            if random.random() < 0.6:  # 60% chance to crack each hash
                fake_hash, plaintext = generate_password_hash(hash_type.lower())
                username = random.choice(['admin', 'user', 'john', 'alice', 'bob'])
                cracked.append((username, plaintext))
                console.print(f"[green]{plaintext:16} ({username})[/green]")
        
        elapsed = time.time() - start_time
        
        # Statistics
        console.print(f"\n[bold white]Session completed[/bold white]")
        console.print(f"[white]Time elapsed: {elapsed:.2f} seconds[/white]")
        console.print(f"[white]Passwords cracked: {len(cracked)}/{ len(cracked) + random.randint(1, 3)}[/white]")
        
        if cracked:
            print_success(f"Cracked {len(cracked)} password(s)")
        
        console.print(f"\n[dim]Use --show to display cracked passwords[/dim]")
    
    def _show_cracked_passwords(self):
        """Show previously cracked passwords"""
        console.print("[bold white]Previously cracked passwords:[/bold white]\n")
        
        for _ in range(random.randint(2, 5)):
            _, plaintext = generate_password_hash()
            username = random.choice(['admin', 'user', 'john', 'alice', 'bob'])
            fake_hash, _ = generate_password_hash()
            console.print(f"[green]{username}:{plaintext}:{fake_hash[:32]}[/green]")
        
        console.print(f"\n[dim]{random.randint(2, 5)} password hash(es) cracked[/dim]")
    
    def _show_help(self):
        """Display John help"""
        help_text = """
[bold cyan]John the Ripper 1.9.0-jumbo-1[/bold cyan]

Usage: john [OPTIONS] [PASSWORD-FILES]

[bold yellow]CRACKING MODES:[/bold yellow]
  [cyan]--single[/cyan]              Single crack mode (uses username info)
  [cyan]--wordlist=FILE[/cyan]       Dictionary mode with wordlist
  [cyan]--incremental[/cyan]         Brute force mode (try all combinations)

[bold yellow]OPTIONS:[/bold yellow]
  [cyan]--rules[/cyan]               Enable word mangling rules
  [cyan]--format=NAME[/cyan]         Force hash format (MD5, SHA256, NTLM, etc.)
  [cyan]--show[/cyan]                Show cracked passwords
  [cyan]--test[/cyan]                Run benchmarks

[bold green]EXAMPLES:[/bold green]
  john --wordlist=/usr/share/wordlists/rockyou.txt hashes.txt
  john --format=raw-md5 --incremental hashes.txt
  john --show hashes.txt

[bold red]SIMULATION MODE:[/bold red]
  No actual hash cracking occurs. All results are simulated.

[dim]https://www.openwall.com/john/[/dim]
"""
        console.print(help_text)
