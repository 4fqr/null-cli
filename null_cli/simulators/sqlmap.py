"""SQLmap SQL injection testing simulator"""
import random
import time
from typing import List, Dict

from .base import ToolSimulator
from ..ui import console, print_error, print_success, print_warning
from ..data.generators import generate_hostname, generate_sql_injection_payloads


class SqlmapSimulator(ToolSimulator):
    """Simulates SQLmap SQL injection detection and exploitation"""
    
    def __init__(self, educational: bool = False):
        super().__init__("sqlmap", educational)
    
    def run(self, args: tuple):
        """Execute sqlmap simulation"""
        self._show_simulation_header()
        
        if not args or '-h' in args or '--help' in args:
            self._show_help()
            return
        
        config = self._parse_arguments(list(args))
        
        if not config['url']:
            print_error("No URL specified. Use -u or --url")
            return
        
        if self.educational:
            self._show_sqlmap_education(config)
        
        self._log_simulation(' '.join(args))
        self._simulate_injection_test(config)
    
    def _parse_arguments(self, args: List[str]) -> Dict:
        """Parse sqlmap arguments"""
        config = {
            'url': None,
            'data': None,
            'cookie': None,
            'level': 1,
            'risk': 1,
            'dbs': False,
            'tables': False,
            'dump': False,
            'batch': False,
        }
        
        for i, arg in enumerate(args):
            if arg in ['-u', '--url'] and i + 1 < len(args):
                config['url'] = args[i + 1]
            elif arg == '--data' and i + 1 < len(args):
                config['data'] = args[i + 1]
            elif arg == '--cookie' and i + 1 < len(args):
                config['cookie'] = args[i + 1]
            elif arg == '--level' and i + 1 < len(args):
                config['level'] = int(args[i + 1])
            elif arg == '--risk' and i + 1 < len(args):
                config['risk'] = int(args[i + 1])
            elif arg == '--dbs':
                config['dbs'] = True
            elif arg == '--tables':
                config['tables'] = True
            elif arg == '--dump':
                config['dump'] = True
            elif arg == '--batch':
                config['batch'] = True
        
        return config
    
    def _show_sqlmap_education(self, config: Dict):
        """Educational information about SQLmap"""
        description_parts = []
        
        description_parts.append("[bold]SQLmap[/bold] - Automated SQL injection detection and exploitation tool.\n\n")
        
        # Basic flags
        description_parts.append("[bold]-u/--url:[/bold] Target URL with injectable parameter.")
        description_parts.append("\n  • Example: -u 'http://site.com/page.php?id=1'")
        description_parts.append("\n  • Tests GET parameters automatically")
        
        if config['data']:
            description_parts.append("\n[bold]--data:[/bold] POST data for testing POST parameters.")
            description_parts.append("\n  • Example: --data 'username=admin&password=test'")
            description_parts.append("\n  • Tests form submissions and POST requests")
        
        # Level and Risk
        description_parts.append(f"\n\n[bold]--level {config['level']} (Detection Depth):[/bold]")
        description_parts.append("\n  • Level 1: Basic GET parameters only")
        description_parts.append("\n  • Level 2: Adds HTTP Cookie headers")
        description_parts.append("\n  • Level 3: Adds User-Agent, Referer headers")
        description_parts.append("\n  • Level 4-5: Exhaustive tests (very slow, many requests)")
        
        description_parts.append(f"\n[bold]--risk {config['risk']} (Attack Risk):[/bold]")
        description_parts.append("\n  • Risk 1: Safe queries (no OR-based, no time-based)")
        description_parts.append("\n  • Risk 2: Heavy queries (time-delays, OR-based)")
        description_parts.append("\n  • Risk 3: OR-based (may UPDATE/DELETE data!)")
        
        # Injection techniques
        description_parts.append("\n\n[bold cyan]SQL Injection Techniques:[/bold cyan]")
        description_parts.append("\n[bold]Boolean-based blind:[/bold] Uses AND/OR to infer true/false. Slow but stealthy.")
        description_parts.append("\n  • id=1 AND 1=1 (true) vs id=1 AND 1=2 (false)")
        description_parts.append("\n[bold]Time-based blind:[/bold] Uses SLEEP() to detect injection via response delay.")
        description_parts.append("\n  • id=1 AND SLEEP(5) - if 5-sec delay, vulnerable")
        description_parts.append("\n[bold]Error-based:[/bold] Forces database errors to leak info.")
        description_parts.append("\n  • MySQL errors reveal version, table names")
        description_parts.append("\n[bold]UNION query:[/bold] Fastest. Appends SELECT to retrieve data directly.")
        description_parts.append("\n  • id=1 UNION SELECT username,password FROM users")
        description_parts.append("\n[bold]Stacked queries:[/bold] Multiple statements. Can INSERT/UPDATE/DELETE.")
        description_parts.append("\n  • id=1; DROP TABLE users-- (Risk 3 only)")
        
        # Enumeration flags
        description_parts.append("\n\n[bold cyan]Data Extraction:[/bold cyan]")
        if config['dbs']:
            description_parts.append("\n[bold]--dbs:[/bold] Enumerate all database names.")
        if config['tables']:
            description_parts.append("\n[bold]--tables:[/bold] List tables in database.")
        if config['dump']:
            description_parts.append("\n[bold]--dump:[/bold] Extract all table contents. Can retrieve thousands of records.")
        
        description_parts.append("\n[bold]-D <db> -T <table> -C <col>:[/bold] Target specific database/table/columns.")
        description_parts.append("\n[bold]--dump-all:[/bold] Dump ENTIRE database server. Extremely noisy.")
        
        # Other useful flags
        description_parts.append("\n\n[bold cyan]Additional Options:[/bold cyan]")
        description_parts.append("\n[bold]--batch:[/bold] Non-interactive mode. Uses default answers (essential for automation).")
        description_parts.append("\n[bold]--random-agent:[/bold] Use random User-Agent to evade detection.")
        description_parts.append("\n[bold]--tamper:[/bold] Apply evasion scripts (space2comment, between, etc) to bypass WAF.")
        description_parts.append("\n[bold]--technique=[/bold] Specify techniques: B(oolean), E(rror), U(nion), S(tacked), T(ime), Q(uery).")
        description_parts.append("\n[bold]--threads=N:[/bold] Parallel requests. Faster but noisier.")
        description_parts.append("\n[bold]--os-shell:[/bold] Attempt interactive OS shell via SQL injection.")
        description_parts.append("\n[bold]--file-read:[/bold] Read files from server (/etc/passwd, config.php).")
        
        # Supported DBMS
        description_parts.append("\n\n[bold]Supported Databases:[/bold] MySQL, PostgreSQL, Oracle, MSSQL, SQLite, MongoDB, Access, Sybase, DB2, Firebird, SAP MaxDB, Informix, etc.")
        
        full_description = ''.join(description_parts)
        
        impact = "[bold red]Real SQLmap Exploitation:[/bold red]\n" \
                "• [red]Data Breach:[/red] Extract entire databases - usernames, passwords, SSNs, credit cards, emails.\n" \
                "• [red]Privilege Escalation:[/red] Read config files with DB admin passwords, AWS keys, API tokens.\n" \
                "• [red]Remote Code Execution:[/red] --os-shell can upload webshells, execute system commands.\n" \
                "• [red]Data Modification:[/red] Risk 3 attacks can UPDATE/DELETE records, drop tables.\n" \
                "• [yellow]Detection:[/yellow] WAFs (ModSecurity, Cloudflare) detect SQLmap signatures. Generates 100-1000s requests.\n" \
                "• [yellow]Logging:[/yellow] Every request logged with IP, timestamp, payload. Forensic evidence.\n" \
                "• [red]Legal:[/red] Unauthorized SQL injection = Computer Fraud and Abuse Act violation. Federal felony.\n\n" \
                "[bold green]Defenses (Priority Order):[/bold green]\n" \
                "1. [green]Parameterized Queries/Prepared Statements:[/green] 100% prevents SQLi. Use ALWAYS.\n" \
                "   • Bad: SELECT * FROM users WHERE id = '$id'\n" \
                "   • Good: SELECT * FROM users WHERE id = ?\n" \
                "2. [green]ORM Frameworks:[/green] SQLAlchemy, Hibernate, Entity Framework - built-in protection.\n" \
                "3. [green]Input Validation:[/green] Whitelist allowed characters, validate data types.\n" \
                "4. [green]Least Privilege:[/green] DB user should only have SELECT on needed tables, no DROP/CREATE.\n" \
                "5. [green]WAF:[/green] ModSecurity, Cloudflare - blocks common SQLi patterns.\n" \
                "6. [green]Error Suppression:[/green] Don't display DB errors to users - log them server-side.\n\n" \
                "[bold cyan]Ethical Use:[/bold cyan] Bug bounties (with scope), authorized pentests, your own apps, CTFs, educational labs."
        
        self._show_educational_info("SQLmap SQL Injection Tool", full_description, impact)
    
    def _simulate_injection_test(self, config: Dict):
        """Simulate SQL injection testing"""
        console.print("[bold cyan]sqlmap/1.7.2#stable (https://sqlmap.org)[/bold cyan]")
        console.print("[yellow]⚠️  SIMULATION MODE - No actual SQL injection testing[/yellow]\n")
        
        url = config['url']
        console.print(f"[cyan][*] Testing URL: {url}[/cyan]")
        console.print(f"[dim][*] Testing parameter(s): id, search, page[/dim]\n")
        
        # Simulate target detection
        time.sleep(0.5)
        console.print(f"[cyan][*] Testing connection to target URL[/cyan]")
        console.print(f"[green][+] Target appears to be reachable[/green]")
        
        # Detect WAF/IPS
        if random.random() < 0.3:
            waf = random.choice(['Cloudflare', 'ModSecurity', 'AWS WAF', 'Imperva'])
            console.print(f"[yellow][!] Heuristic (basic) test shows site might be protected by {waf}[/yellow]")
        
        console.print(f"\n[cyan][*] Testing for SQL injection vulnerabilities[/cyan]\n")
        
        # Test different injection types
        payloads = generate_sql_injection_payloads()
        vulnerable = False
        vuln_type = None
        
        for payload in payloads:
            time.sleep(random.uniform(0.2, 0.5))
            console.print(f"[dim]Testing {payload['type']}...[/dim]")
            
            if payload['vulnerable']:
                vulnerable = True
                vuln_type = payload['type']
                print_success(f"Parameter appears to be vulnerable to {payload['type']} injection")
                break
        
        if vulnerable:
            console.print(f"\n[bold green]Vulnerability detected![/bold green]\n")
            
            # Database enumeration
            console.print(f"[cyan][*] Identifying database backend[/cyan]")
            time.sleep(0.3)
            db_type = random.choice(['MySQL', 'PostgreSQL', 'MSSQL', 'Oracle'])
            db_version = random.choice(['5.7.33', '8.0.23', '13.4', '2019'])
            console.print(f"[green][+] Backend DBMS: {db_type} {db_version}[/green]")
            
            # Get databases
            if config['dbs']:
                console.print(f"\n[cyan][*] Enumerating databases[/cyan]")
                time.sleep(0.5)
                databases = ['information_schema', 'mysql', 'webapp_db', 'users_db']
                console.print(f"[green][+] Available databases [{len(databases)}]:[/green]")
                for db in databases:
                    console.print(f"[white]    {db}[/white]")
            
            # Get tables
            if config['tables']:
                console.print(f"\n[cyan][*] Enumerating tables in 'webapp_db'[/cyan]")
                time.sleep(0.5)
                tables = ['users', 'products', 'orders', 'sessions', 'admin_log']
                console.print(f"[green][+] Database tables [{len(tables)}]:[/green]")
                for table in tables:
                    console.print(f"[white]    {table}[/white]")
            
            # Dump data
            if config['dump']:
                console.print(f"\n[cyan][*] Dumping table 'users'[/cyan]")
                time.sleep(1.0)
                console.print(f"[green][+] Retrieved entries:[/green]\n")
                console.print("[white]id | username | email | password_hash[/white]")
                console.print("[white]" + "-" * 60 + "[/white]")
                for i in range(1, random.randint(3, 6)):
                    username = f"user{i}"
                    email = f"user{i}@example.com"
                    hash_val = "5f4dcc3b5aa765d61d8327deb882cf99"
                    console.print(f"[white]{i}  | {username:8} | {email:20} | {hash_val}[/white]")
                
                print_warning("Database dumping would expose sensitive user information!")
        else:
            console.print(f"\n[yellow][!] Parameter does not appear to be injectable[/yellow]")
            console.print(f"[dim]Try increasing --level and --risk for more tests[/dim]")
        
        console.print(f"\n[dim]SIMULATION COMPLETE - No actual SQL queries were executed[/dim]")
    
    def _show_help(self):
        """Display sqlmap help"""
        help_text = """
[bold cyan]sqlmap/1.7.2#stable - Automatic SQL injection tool[/bold cyan]

Usage: python sqlmap.py [options]

[bold yellow]TARGET:[/bold yellow]
  [cyan]-u URL, --url=URL[/cyan]   Target URL
  [cyan]--data=DATA[/cyan]         Data string for POST
  [cyan]--cookie=COOKIE[/cyan]     HTTP Cookie header value

[bold yellow]DETECTION:[/bold yellow]
  [cyan]--level=LEVEL[/cyan]       Level of tests (1-5, default 1)
  [cyan]--risk=RISK[/cyan]         Risk of tests (1-3, default 1)
  [cyan]--technique=TECH[/cyan]    SQL injection techniques to test

[bold yellow]ENUMERATION:[/bold yellow]
  [cyan]--dbs[/cyan]               Enumerate databases
  [cyan]--tables[/cyan]            Enumerate tables
  [cyan]--columns[/cyan]           Enumerate columns
  [cyan]--dump[/cyan]              Dump table entries
  [cyan]--dump-all[/cyan]          Dump all database tables

[bold yellow]GENERAL:[/bold yellow]
  [cyan]--batch[/cyan]             Never ask for user input (non-interactive)
  [cyan]--random-agent[/cyan]      Use random User-Agent header

[bold green]EXAMPLES:[/bold green]
  sqlmap -u "http://example.com/page?id=1" --dbs
  sqlmap -u "http://example.com/page?id=1" --tables -D webapp_db
  sqlmap -u "http://example.com/page?id=1" --dump -T users

[bold red]SIMULATION MODE:[/bold red]
  No actual SQL injection testing. All results are simulated.

[dim]https://sqlmap.org[/dim]
"""
        console.print(help_text)
