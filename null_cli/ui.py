"""Beautiful terminal UI components for null-cli"""
from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich.table import Table
from pyfiglet import Figlet
import random


console = Console()


def print_banner():
    """Display beautiful ASCII banner with gradient colors"""
    fig = Figlet(font='slant')
    banner_text = fig.renderText('NULL-CLI')
    
    # Create gradient effect
    colors = ['bright_cyan', 'cyan', 'blue', 'bright_blue']
    lines = banner_text.split('\n')
    
    styled_lines = []
    for i, line in enumerate(lines):
        color = colors[i % len(colors)]
        styled_lines.append(f"[{color}]{line}[/{color}]")
    
    banner = '\n'.join(styled_lines)
    
    console.print(Panel(
        banner + "\n\n[bright_white]Safely simulate Kali Linux security tools without any risk[/bright_white]\n"
        "[dim]Educational tool for learning offensive security concepts[/dim]",
        border_style="bright_cyan",
        padding=(1, 2)
    ))


def print_simulation_header(tool_name: str):
    """Print simulation mode header"""
    header = Text()
    header.append("╔" + "═" * 78 + "╗\n", style="bright_yellow")
    header.append("║ ", style="bright_yellow")
    header.append("🎯 SIMULATION MODE", style="bold bright_red")
    header.append(" - No actual network traffic or exploits generated", style="bright_white")
    header.append(" " * (78 - 62) + "║\n", style="bright_yellow")
    header.append("║ ", style="bright_yellow")
    header.append(f"Simulating: {tool_name.upper()}", style="bright_cyan")
    header.append(" " * (78 - len(f"Simulating: {tool_name.upper()}") - 2) + "║\n", style="bright_yellow")
    header.append("╚" + "═" * 78 + "╝", style="bright_yellow")
    
    console.print(header)
    console.print()


def print_educational_info(title: str, description: str, real_world_impact: str):
    """Display educational information about a command"""
    table = Table(title="📚 Educational Mode", border_style="bright_magenta", show_header=False)
    table.add_column("Field", style="bold cyan")
    table.add_column("Information", style="white")
    
    table.add_row("Command", title)
    table.add_row("What it does", description)
    table.add_row("Real-world impact", real_world_impact)
    
    console.print(table)
    console.print()


def print_warning(message: str):
    """Print warning message"""
    console.print(f"[bold yellow]⚠️  WARNING:[/bold yellow] {message}")


def print_error(message: str):
    """Print error message"""
    console.print(f"[bold red]❌ ERROR:[/bold red] {message}")


def print_success(message: str):
    """Print success message"""
    console.print(f"[bold green]✅ SUCCESS:[/bold green] {message}")


def print_info(message: str):
    """Print info message"""
    console.print(f"[cyan]ℹ️  INFO:[/cyan] {message}")


def create_tools_table():
    """Create a table of supported tools"""
    table = Table(title="🛠️  Supported Tools", border_style="bright_cyan")
    
    table.add_column("Tool", style="bold cyan", width=15)
    table.add_column("Category", style="magenta", width=20)
    table.add_column("Accuracy", style="yellow", width=10)
    table.add_column("Educational", style="green", width=12)
    table.add_column("Status", style="white")
    
    # Network scanners
    table.add_row("nmap", "Network Scanner", "★★★★★", "✅", "Fully implemented")
    
    # Exploitation
    table.add_row("metasploit", "Exploitation Framework", "★★★★★", "✅", "Fully implemented")
    
    # Password tools
    table.add_row("hydra", "Password Brute-Force", "★★★★★", "✅", "Fully implemented")
    table.add_row("john", "Hash Cracking", "★★★★★", "✅", "Fully implemented")
    
    # Web security
    table.add_row("sqlmap", "SQL Injection", "★★★★★", "✅", "Fully implemented")
    table.add_row("nikto", "Web Vulnerability", "★★★★☆", "✅", "Fully implemented")
    table.add_row("gobuster", "Directory Brute-Force", "★★★★★", "✅", "Fully implemented")
    table.add_row("wpscan", "WordPress Scanner", "★★★★☆", "✅", "Fully implemented")
    
    return table


def print_simulation_watermark():
    """Print subtle simulation watermark in corner"""
    console.print("[dim bright_black]┌────────────────┐[/dim bright_black]")
    console.print("[dim bright_black]│ SIMULATION MODE│[/dim bright_black]")
    console.print("[dim bright_black]└────────────────┘[/dim bright_black]")
