"""Metasploit Framework simulator"""
import random
import time
from typing import List, Dict, Optional

from .base import ToolSimulator
from ..ui import console, print_warning, print_info, print_success
from ..data.generators import (
    generate_fake_ip, generate_local_ip, generate_exploit_payload,
    generate_session_id, generate_metasploit_modules, generate_os_detection
)


class MetasploitSimulator(ToolSimulator):
    """Simulates Metasploit Framework (msfconsole)"""
    
    def __init__(self, educational: bool = False):
        super().__init__("metasploit", educational)
        self.current_module = None
        self.module_options = {}
        self.sessions = {}
        self.current_session = None
        
    def run(self, args: tuple):
        """Execute metasploit simulation"""
        self._show_simulation_header()
        
        # Educational info
        if self.educational:
            self._show_metasploit_education()
        
        # Start interactive console
        self._start_msfconsole()
        
    def _show_metasploit_education(self):
        """Show educational information about Metasploit"""
        description = "[bold]Metasploit Framework[/bold] - Most popular exploitation framework. 2000+ exploits, 500+ payloads.\n\n"
        description += "[bold cyan]Metasploit Components:[/bold cyan]\n"
        description += "[bold]msfconsole:[/bold] Primary interface (what you're using).\n"
        description += "[bold]Exploits:[/bold] Code that takes advantage of specific vulnerabilities.\n"
        description += "  • Example: exploit/windows/smb/ms17_010_eternalblue (WannaCry vulnerability)\n"
        description += "[bold]Payloads:[/bold] Code executed after successful exploit.\n"
        description += "  • [cyan]Reverse Shell:[/cyan] Target connects back to attacker. Bypasses firewalls.\n"
        description += "  • [cyan]Bind Shell:[/cyan] Opens port on target for attacker to connect.\n"
        description += "  • [cyan]Meterpreter:[/cyan] Advanced payload with file upload/download, keylogging, screenshot, webcam.\n"
        description += "[bold]Auxiliary:[/bold] Non-exploit modules (scanners, fuzzers, DoS).\n"
        description += "[bold]Post:[/bold] Post-exploitation modules (privilege escalation, password dumping).\n"
        description += "[bold]Encoders:[/bold] Obfuscate payloads to evade antivirus.\n\n"
        description += "[bold cyan]Key msfconsole Commands:[/bold cyan]\n"
        description += "[bold]search <term>:[/bold] Find exploits/modules.\n"
        description += "  • search eternalblue\n"
        description += "  • search type:exploit platform:windows cve:2017\n"
        description += "[bold]use <module>:[/bold] Select exploit/auxiliary module.\n"
        description += "  • use exploit/windows/smb/ms17_010_eternalblue\n"
        description += "[bold]show options:[/bold] Display required/optional parameters.\n"
        description += "[bold]set <option> <value>:[/bold] Configure module.\n"
        description += "  • set RHOSTS 192.168.1.100 (target IP)\n"
        description += "  • set LHOST 192.168.1.50 (your IP for reverse shell)\n"
        description += "  • set LPORT 4444 (your listening port)\n"
        description += "  • set PAYLOAD windows/meterpreter/reverse_tcp\n"
        description += "[bold]exploit / run:[/bold] Execute the module.\n"
        description += "[bold]sessions:[/bold] Manage active sessions.\n"
        description += "  • sessions -l (list sessions)\n"
        description += "  • sessions -i 1 (interact with session 1)\n"
        description += "[bold]background:[/bold] Background current session (Ctrl+Z).\n"
        description += "[bold]db_nmap:[/bold] Run nmap and import results to Metasploit database.\n"
        description += "[bold]check:[/bold] Test if target is vulnerable (non-exploiting).\n\n"
        description += "[bold cyan]Meterpreter Commands (Post-Exploitation):[/bold cyan]\n"
        description += "[bold]sysinfo:[/bold] Display system information.\n"
        description += "[bold]getuid:[/bold] Get current user.\n"
        description += "[bold]getsystem:[/bold] Attempt privilege escalation to SYSTEM.\n"
        description += "[bold]hashdump:[/bold] Dump password hashes (requires SYSTEM).\n"
        description += "[bold]screenshot:[/bold] Capture screenshot.\n"
        description += "[bold]keyscan_start:[/bold] Start keylogger.\n"
        description += "[bold]upload/download:[/bold] File transfer.\n"
        description += "[bold]shell:[/bold] Drop into system shell.\n"
        description += "[bold]persistence:[/bold] Create backdoor that survives reboots."
        
        impact = "[bold red]Real Metasploit Impact:[/bold red]\n" \
                "• [red]Full System Compromise:[/red] Successful exploit often = SYSTEM/root access.\n" \
                "• [red]Persistent Access:[/red] Backdoors survive reboots, updates, even OS reinstalls.\n" \
                "• [red]Data Exfiltration:[/red] Download files, databases, password hashes, SSH keys.\n" \
                "• [red]Lateral Movement:[/red] Use compromised host to attack other network systems.\n" \
                "• [red]Destructive Actions:[/red] Delete logs, corrupt files, deploy ransomware.\n" \
                "• [yellow]Detection:[/yellow]\n" \
                "  - Antivirus detects known payloads (use encoders/custom payloads)\n" \
                "  - Network IDS detects exploit traffic patterns\n" \
                "  - EDR (Endpoint Detection & Response) detects post-exploitation behavior\n" \
                "  - SIEM correlates suspicious activities\n" \
                "• [red]Legal:[/red] Unauthorized exploitation = Computer Fraud and Abuse Act. Federal felony. 5-20 years prison.\n\n" \
                "[bold green]Defenses (Defense in Depth):[/bold green]\n" \
                "1. [green]Patch Management:[/green] Update systems immediately. Most exploits target known vulnerabilities.\n" \
                "2. [green]Network Segmentation:[/green] VLANs, firewalls limit lateral movement.\n" \
                "3. [green]Least Privilege:[/green] Users shouldn't have admin rights. Limits post-exploitation.\n" \
                "4. [green]Antivirus/EDR:[/green] Detects known payloads, behavioral analysis.\n" \
                "5. [green]IDS/IPS:[/green] Snort, Suricata detect exploit traffic.\n" \
                "6. [green]Application Whitelisting:[/green] Only allow approved executables.\n" \
                "7. [green]Disable Unnecessary Services:[/green] SMBv1, Telnet, FTP often exploited.\n" \
                "8. [green]Monitor Outbound:[/green] Reverse shells create unusual outbound connections.\n" \
                "9. [green]Log Analysis:[/green] SIEM detects anomalies (new service, unusual process).\n" \
                "10. [green]Backups:[/green] Offline backups for ransomware recovery.\n\n" \
                "[bold cyan]Ethical Use ONLY:[/bold cyan]\n" \
                "• Authorized penetration tests with written contract\n" \
                "• Bug bounties within defined scope\n" \
                "• Your own lab environment (VirtualBox, VMware)\n" \
                "• CTF competitions, HackTheBox, TryHackMe\n" \
                "• Education with vulnerable VMs (Metasploitable, DVWA)"
        
        self._show_educational_info("Metasploit Framework", description, impact)
        
    def _start_msfconsole(self):
        """Start interactive Metasploit console"""
        # ASCII banner
        self._print_msf_banner()
        
        console.print("\n[green]msf6 >[/green] ", end='')
        console.print("[dim]Type 'help' for commands, 'exit' to quit[/dim]\n")
        
        # Simulate interactive commands
        self._interactive_mode()
        
    def _print_msf_banner(self):
        """Print Metasploit ASCII banner"""
        banner = """
[bright_red]                 ________________
              /                \
             /    SIMULATION     \
            /        MODE          \
           /      METASPLOIT        \
          /__________________________|

       =[ [bold cyan]metasploit v6.3.4-dev[/bold cyan]                      ]
+ -- --=[ 2295 exploits - 1201 auxiliary - 409 post       ]
+ -- --=[ 968 payloads - 45 encoders - 11 nops            ]
+ -- --=[ 9 evasion                                       ]
[/bright_red]
[yellow]⚠️  SIMULATION MODE - No actual exploits will be executed[/yellow]
"""
        console.print(banner)
        
    def _interactive_mode(self):
        """Simulate interactive MSF console (predefined workflow)"""
        # Predefined realistic workflow
        workflow = [
            ("search eternalblue", self._cmd_search),
            ("use exploit/windows/smb/ms17_010_eternalblue", self._cmd_use),
            ("show options", self._cmd_show_options),
            ("set RHOSTS 192.0.2.45", self._cmd_set_option),
            ("set LHOST 192.0.2.10", self._cmd_set_option),
            ("exploit", self._cmd_exploit),
            ("sessions -l", self._cmd_sessions_list),
            ("sessions -i 1", self._cmd_sessions_interact),
        ]
        
        for command, handler in workflow:
            console.print(f"[green]msf6{self._get_prompt_suffix()} >[/green] [white]{command}[/white]")
            time.sleep(0.5)
            handler(command)
            console.print()
            time.sleep(1.0)
        
        console.print(f"[green]msf6{self._get_prompt_suffix()} >[/green] [white]exit[/white]")
        console.print("[cyan][*][/cyan] Exiting msfconsole simulation\n")
        
    def _get_prompt_suffix(self) -> str:
        """Get prompt suffix based on current module"""
        if self.current_module:
            return f" {self.current_module}"
        return ""
        
    def _cmd_search(self, command: str):
        """Simulate search command"""
        query = command.split("search ", 1)[1] if "search " in command else ""
        
        console.print("[cyan][*][/cyan] Searching module database...")
        self._simulate_delay(0.3, 0.8)
        
        # Show fake search results
        console.print("\n[bold white]Matching Modules[/bold white]")
        console.print("[bold white]" + "=" * 80 + "[/bold white]\n")
        
        modules = generate_metasploit_modules()
        
        console.print(f"   [bold]#  Name{' ' * 50}Disclosure Date  Rank[/bold]")
        console.print(f"   [bold]-  ----{' ' * 50}---------------  ----[/bold]")
        
        for i, module in enumerate(modules):
            name_display = module['name'][:50].ljust(50)
            console.print(f"   [cyan]{i}[/cyan]  {name_display}  [dim]{module['date']}[/dim]  [green]{module['rank']}[/green]")
        
        console.print(f"\n[dim]Interact with a module by name or index. For example: use {modules[0]['name']}[/dim]")
        
    def _cmd_use(self, command: str):
        """Simulate use command"""
        module_path = command.split("use ", 1)[1] if "use " in command else ""
        self.current_module = module_path
        
        # Set default options
        self.module_options = {
            "RHOSTS": {"required": True, "value": None, "description": "The target host(s)"},
            "RPORT": {"required": True, "value": "445", "description": "The target port (TCP)"},
            "LHOST": {"required": True, "value": None, "description": "The listen address"},
            "LPORT": {"required": False, "value": "4444", "description": "The listen port"},
            "PAYLOAD": {"required": True, "value": "windows/x64/meterpreter/reverse_tcp", "description": "Payload to use"},
        }
        
        console.print(f"[cyan][*][/cyan] Using configured payload {self.module_options['PAYLOAD']['value']}")
        
    def _cmd_show_options(self, command: str):
        """Simulate show options command"""
        if not self.current_module:
            console.print("[red][-][/red] No module selected")
            return
        
        console.print("\n[bold white]Module options ({}):[/bold white]\n".format(self.current_module))
        
        console.print(f"   [bold]Name       Current Setting  Required  Description[/bold]")
        console.print(f"   [bold]----       ---------------  --------  -----------[/bold]")
        
        for name, opt in self.module_options.items():
            value = opt['value'] or ""
            required = "yes" if opt['required'] else "no"
            desc = opt['description']
            
            value_display = str(value).ljust(16)
            console.print(f"   [cyan]{name:10}[/cyan] {value_display} [yellow]{required:8}[/yellow]  [dim]{desc}[/dim]")
        
        console.print(f"\n[bold white]Payload options ({self.module_options['PAYLOAD']['value']}):[/bold white]\n")
        console.print(f"   [bold]Name   Current Setting  Required  Description[/bold]")
        console.print(f"   [bold]----   ---------------  --------  -----------[/bold]")
        console.print(f"   [cyan]LHOST[/cyan]  {(self.module_options['LHOST']['value'] or ''):16} [yellow]yes     [/yellow]  [dim]The listen address[/dim]")
        console.print(f"   [cyan]LPORT[/cyan]  {self.module_options['LPORT']['value']:16} [yellow]yes     [/yellow]  [dim]The listen port[/dim]")
        
    def _cmd_set_option(self, command: str):
        """Simulate set command"""
        parts = command.split()
        if len(parts) >= 3:
            option_name = parts[1].upper()
            option_value = parts[2]
            
            if option_name in self.module_options:
                self.module_options[option_name]['value'] = option_value
                console.print(f"[cyan]{option_name}[/cyan] => {option_value}")
            else:
                console.print(f"[red][-][/red] Unknown option: {option_name}")
        
    def _cmd_exploit(self, command: str):
        """Simulate exploit execution"""
        if not self.current_module:
            console.print("[red][-][/red] No module selected")
            return
        
        # Check required options
        missing = [name for name, opt in self.module_options.items() 
                  if opt['required'] and not opt['value']]
        
        if missing:
            console.print(f"[red][-][/red] Missing required options: {', '.join(missing)}")
            return
        
        # Simulate exploit
        console.print(f"[cyan][*][/cyan] Started reverse TCP handler on {self.module_options['LHOST']['value']}:{self.module_options['LPORT']['value']}")
        self._simulate_delay(0.5, 1.0)
        
        target = self.module_options['RHOSTS']['value']
        console.print(f"[cyan][*][/cyan] {target}:{self.module_options['RPORT']['value']} - Connecting to target...")
        self._simulate_delay(0.3, 0.8)
        
        # Simulate target detection
        os_info = generate_os_detection()
        console.print(f"[cyan][*][/cyan] {target}:{self.module_options['RPORT']['value']} - SIMULATION: Target appears to be {os_info['name']}")
        self._simulate_delay(0.5, 1.0)
        
        # Simulate exploitation
        console.print(f"[cyan][*][/cyan] {target}:{self.module_options['RPORT']['value']} - SIMULATION: Attempting exploitation...")
        self._simulate_delay(1.0, 2.0)
        
        console.print(f"[cyan][*][/cyan] {target}:{self.module_options['RPORT']['value']} - SIMULATION: Exploiting target...")
        self._simulate_delay(0.8, 1.5)
        
        # Simulate success
        session_id = generate_session_id()
        console.print(f"[cyan][*][/cyan] {target}:{self.module_options['RPORT']['value']} - SIMULATION: Sending stage ({random.randint(170000, 200000)} bytes)")
        self._simulate_delay(0.5, 1.0)
        
        console.print(f"[green][+][/green] {target}:{self.module_options['RPORT']['value']} - SIMULATION: Meterpreter session {session_id} opened")
        console.print(f"[cyan][*][/cyan] Session {session_id} created in the background")
        
        # Store session
        self.sessions[session_id] = {
            "id": session_id,
            "type": "meterpreter",
            "target": target,
            "payload": self.module_options['PAYLOAD']['value']
        }
        
    def _cmd_sessions_list(self, command: str):
        """Simulate sessions -l command"""
        if not self.sessions:
            console.print("[yellow][!][/yellow] No active sessions.")
            return
        
        console.print("\n[bold white]Active sessions[/bold white]")
        console.print("[bold white]" + "=" * 80 + "[/bold white]\n")
        
        console.print(f"  [bold]Id  Name  Type         Information  Connection[/bold]")
        console.print(f"  [bold]--  ----  ----         -----------  ----------[/bold]")
        
        for session_id, session in self.sessions.items():
            conn = f"{session['target']}:445 -> {self.module_options['LHOST']['value']}:{self.module_options['LPORT']['value']}"
            console.print(f"  [cyan]{session_id:2}[/cyan]        [green]{session['type']:12}[/green] [dim]NT AUTHORITY\\SYSTEM[/dim]  [dim]{conn}[/dim]")
        
    def _cmd_sessions_interact(self, command: str):
        """Simulate sessions -i command"""
        parts = command.split()
        if len(parts) < 3:
            console.print("[red][-][/red] Usage: sessions -i <session_id>")
            return
        
        try:
            session_id = int(parts[2])
            if session_id not in self.sessions:
                console.print(f"[red][-][/red] Invalid session ID: {session_id}")
                return
        except ValueError:
            console.print("[red][-][/red] Session ID must be a number")
            return
        
        self.current_session = session_id
        session = self.sessions[session_id]
        
        console.print(f"[cyan][*][/cyan] Starting interaction with session {session_id}...")
        self._simulate_delay(0.3, 0.6)
        
        console.print(f"\n[green]meterpreter >[/green] [dim]Type 'help' for commands[/dim]")
        
        # Simulate some meterpreter commands
        self._simulate_meterpreter_session()
        
    def _simulate_meterpreter_session(self):
        """Simulate interactive meterpreter session"""
        commands = [
            ("sysinfo", self._meterpreter_sysinfo),
            ("getuid", self._meterpreter_getuid),
            ("ps", self._meterpreter_ps),
            ("background", self._meterpreter_background),
        ]
        
        for cmd, handler in commands:
            time.sleep(1.0)
            console.print(f"[green]meterpreter >[/green] [white]{cmd}[/white]")
            time.sleep(0.3)
            handler()
            console.print()
        
    def _meterpreter_sysinfo(self):
        """Simulate sysinfo command"""
        os_info = generate_os_detection()
        console.print("[cyan]Computer[/cyan]        : " + f"WIN-{random.randint(1000000, 9999999)}")
        console.print("[cyan]OS[/cyan]              : " + os_info['name'])
        console.print("[cyan]Architecture[/cyan]    : x64")
        console.print("[cyan]System Language[/cyan] : en_US")
        console.print("[cyan]Domain[/cyan]          : WORKGROUP")
        console.print("[cyan]Logged On Users[/cyan] : " + str(random.randint(1, 5)))
        console.print("[yellow]⚠️  SIMULATION: No actual system access[/yellow]")
        
    def _meterpreter_getuid(self):
        """Simulate getuid command"""
        console.print("[cyan]Server username:[/cyan] NT AUTHORITY\\SYSTEM")
        console.print("[yellow]⚠️  SIMULATION: Not actually running as SYSTEM[/yellow]")
        
    def _meterpreter_ps(self):
        """Simulate ps command"""
        console.print("\n[bold white]Process List[/bold white]\n")
        console.print(f"[bold] PID   PPID  Name                  Arch  User[/bold]")
        console.print(f"[bold] ---   ----  ----                  ----  ----[/bold]")
        
        processes = [
            (4, 0, "System", "x64", "NT AUTHORITY\\SYSTEM"),
            (624, 4, "smss.exe", "x64", "NT AUTHORITY\\SYSTEM"),
            (812, 804, "csrss.exe", "x64", "NT AUTHORITY\\SYSTEM"),
            (916, 804, "wininit.exe", "x64", "NT AUTHORITY\\SYSTEM"),
            (1024, 916, "services.exe", "x64", "NT AUTHORITY\\SYSTEM"),
            (1032, 916, "lsass.exe", "x64", "NT AUTHORITY\\SYSTEM"),
        ]
        
        for pid, ppid, name, arch, user in processes:
            console.print(f" [cyan]{pid:4}[/cyan]  {ppid:4}  {name:20}  {arch:4}  [dim]{user}[/dim]")
        
        console.print(f"\n[yellow]⚠️  SIMULATION: Fake process list[/yellow]")
        
    def _meterpreter_background(self):
        """Simulate background command"""
        console.print(f"[cyan][*][/cyan] Backgrounding session {self.current_session}...")
        self.current_session = None
