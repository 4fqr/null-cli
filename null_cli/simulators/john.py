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
        description = "John the Ripper is a password cracking tool that uses various " \
                     "techniques to crack password hashes:\n\n" \
                     "• Dictionary attack: Tests passwords from wordlists\n" \
                     "• Brute-force: Tries all possible character combinations\n" \
                     "• Rules: Applies mutations to dictionary words (l33t speak, etc.)\n" \
                     "• Single crack: Uses username/GECOS information\n\n" \
                     "Supports many hash types: MD5, SHA, bcrypt, NTLM, and hundreds more."
        
        impact = "[bold red]Real John attacks would:[/bold red]\n" \
                "• Require possession of stolen password hashes (from breach)\n" \
                "• Consume massive CPU/GPU resources\n" \
                "• Run for days/weeks/months depending on hash strength\n" \
                "• Reveal weak passwords in minutes to hours\n" \
                "• Strong passwords (12+ chars, complex) may never be cracked\n\n" \
                "[bold yellow]Defense:[/bold yellow]\n" \
                "• Use strong, unique passwords (14+ characters)\n" \
                "• Enable multi-factor authentication\n" \
                "• Use modern hash algorithms (bcrypt, Argon2)\n" \
                "• Implement password complexity requirements"
        
        self._show_educational_info("John the Ripper Hash Cracking", description, impact)
    
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
