"""Main CLI entry point for null-cli"""
import click
from rich.prompt import Prompt, Confirm
from rich import print as rprint

from .config import ConfigManager
from .ui import (
    console, print_banner, print_simulation_header, 
    print_error, print_info, print_success, create_tools_table
)
from .simulators import (
    NmapSimulator, MetasploitSimulator, HydraSimulator,
    JohnSimulator, SqlmapSimulator, NiktoSimulator,
    GobusterSimulator, WPScanSimulator
)


config = ConfigManager()


@click.group(invoke_without_command=True)
@click.pass_context
def cli(ctx):
    """🎯 null-cli: Safely simulate Kali Linux security tools without any risk
    
    Educational tool for learning offensive security concepts with zero real-world impact.
    """
    if ctx.invoked_subcommand is None:
        print_banner()
        
        # First run experience
        if config.get('first_run', True):
            first_run_setup()
        else:
            show_main_menu()


def first_run_setup():
    """Interactive first-run setup"""
    console.print("\n[bold bright_cyan]👋 Welcome to null-cli![/bold bright_cyan]\n")
    console.print("This tool lets you safely learn offensive security tools without performing")
    console.print("any real network operations or exploits. Perfect for education and practice!\n")
    
    # Show supported tools
    console.print(create_tools_table())
    console.print()
    
    # Ask for favorite tool
    favorite = Prompt.ask(
        "[cyan]Which tool would you like to try first?[/cyan]",
        choices=["nmap", "metasploit", "hydra", "sqlmap", "nikto", "skip"],
        default="nmap"
    )
    
    if favorite != "skip":
        config.set('favorite_tool', favorite)
        print_success(f"Set {favorite} as your default tool!")
    
    # Ask about educational mode
    educational = Confirm.ask(
        "[cyan]Enable educational mode? (Shows explanations of what real commands would do)[/cyan]",
        default=True
    )
    config.set('educational_mode', educational)
    
    # Mark first run complete
    config.set('first_run', False)
    
    console.print("\n[bold green]✅ Setup complete! You're ready to start learning.[/bold green]\n")
    console.print("[dim]Run 'null-cli --help' to see all available commands.[/dim]\n")


def show_main_menu():
    """Show main menu for returning users"""
    console.print("\n[bold bright_cyan]What would you like to do?[/bold bright_cyan]\n")
    console.print("  [cyan]1.[/cyan] Simulate a tool (null-cli use <tool>)")
    console.print("  [cyan]2.[/cyan] View command history (null-cli history)")
    console.print("  [cyan]3.[/cyan] Change settings (null-cli config)")
    console.print("  [cyan]4.[/cyan] See supported tools (null-cli tools)")
    console.print("\n[dim]Run 'null-cli --help' for full documentation[/dim]\n")


@cli.command(context_settings=dict(ignore_unknown_options=True, allow_extra_args=True))
@click.argument('tool')
@click.option('--educational', is_flag=True, help='Show educational information about the command')
@click.option('--paranoia', is_flag=True, help='Require confirmation before simulating')
@click.pass_context
def use(ctx, tool, educational, paranoia):
    """Simulate a security tool in safe mode
    
    Examples:
        null-cli use nmap -sV -p 80,443 scanme.nmap.org
        null-cli use metasploit
        null-cli use nmap --help
    """
    tool = tool.lower()
    args = tuple(ctx.args)  # Get remaining arguments from context
    
    # Check if educational mode is globally enabled
    if not educational and config.get('educational_mode', False):
        educational = True
    
    # Check if paranoia mode is globally enabled
    if not paranoia and config.get('paranoia_mode', False):
        paranoia = True
    
    # Paranoia mode confirmation
    if paranoia:
        command_str = f"{tool} {' '.join(args)}"
        confirmed = Confirm.ask(
            f"[yellow]⚠️  Paranoia mode: Confirm simulation of '{command_str}'?[/yellow]",
            default=True
        )
        if not confirmed:
            print_info("Simulation cancelled by user")
            return
    
    # Log the command
    config.log_command(tool, ' '.join(args))
    
    # Route to appropriate simulator
    simulators = {
        'nmap': NmapSimulator,
        'metasploit': MetasploitSimulator,
        'msfconsole': MetasploitSimulator,
        'msf': MetasploitSimulator,
        'hydra': HydraSimulator,
        'john': JohnSimulator,
        'sqlmap': SqlmapSimulator,
        'nikto': NiktoSimulator,
        'gobuster': GobusterSimulator,
        'wpscan': WPScanSimulator,
    }
    
    if tool in simulators:
        simulator = simulators[tool](educational=educational)
        simulator.run(args)
    else:
        print_error(f"Tool '{tool}' is not yet supported")
        console.print("\n[bold cyan]Supported tools:[/bold cyan]")
        console.print("[white]• nmap - Network port scanner[/white]")
        console.print("[white]• metasploit - Exploitation framework[/white]")
        console.print("[white]• hydra - Password brute-forcing[/white]")
        console.print("[white]• john - Password hash cracking[/white]")
        console.print("[white]• sqlmap - SQL injection testing[/white]")
        console.print("[white]• nikto - Web vulnerability scanner[/white]")
        console.print("[white]• gobuster - Directory brute-forcing[/white]")
        console.print("[white]• wpscan - WordPress security scanner[/white]")
        console.print("\n[dim]Run 'null-cli tools' to see all available tools[/dim]\n")


@cli.command()
def tools():
    """List all supported tools and their simulation accuracy"""
    print_banner()
    console.print(create_tools_table())
    console.print()


@cli.command()
@click.option('--limit', default=50, help='Number of recent commands to show')
def history(limit):
    """View recent simulation history"""
    print_banner()
    console.print("[bold bright_cyan]📜 Recent Command History[/bold bright_cyan]\n")
    
    history_entries = config.get_history(limit)
    
    if not history_entries:
        print_info("No command history yet. Start by running 'null-cli use nmap --help'")
        return
    
    for entry in history_entries:
        console.print(f"  [dim]{entry.strip()}[/dim]")
    
    console.print()


@cli.command()
def config_cmd():
    """Configure null-cli preferences"""
    print_banner()
    console.print("[bold bright_cyan]⚙️  Configuration[/bold bright_cyan]\n")
    
    # Show current settings
    console.print("[white]Current settings:[/white]")
    console.print(f"  Educational mode: [cyan]{config.get('educational_mode', False)}[/cyan]")
    console.print(f"  Paranoia mode: [cyan]{config.get('paranoia_mode', False)}[/cyan]")
    console.print(f"  Favorite tool: [cyan]{config.get('favorite_tool', 'None')}[/cyan]")
    console.print()
    
    # Interactive configuration
    if Confirm.ask("[cyan]Would you like to change settings?[/cyan]", default=False):
        educational = Confirm.ask(
            "[cyan]Enable educational mode?[/cyan]",
            default=config.get('educational_mode', False)
        )
        config.set('educational_mode', educational)
        
        paranoia = Confirm.ask(
            "[cyan]Enable paranoia mode? (Requires confirmation for each command)[/cyan]",
            default=config.get('paranoia_mode', False)
        )
        config.set('paranoia_mode', paranoia)
        
        print_success("Settings updated!")
    
    console.print()


@cli.command()
def reset():
    """Reset null-cli to default settings"""
    if Confirm.ask("[yellow]⚠️  Are you sure you want to reset all settings?[/yellow]", default=False):
        config.set('first_run', True)
        config.set('educational_mode', False)
        config.set('paranoia_mode', False)
        config.set('favorite_tool', None)
        print_success("Settings reset! Run 'null-cli' to go through setup again.")
    else:
        print_info("Reset cancelled")


if __name__ == '__main__':
    cli()
