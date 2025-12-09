"""Tool simulators for null-cli"""

from .base import ToolSimulator
from .nmap import NmapSimulator
from .metasploit import MetasploitSimulator
from .hydra import HydraSimulator
from .john import JohnSimulator
from .sqlmap import SqlmapSimulator
from .nikto import NiktoSimulator
from .gobuster import GobusterSimulator
from .wpscan import WPScanSimulator

__all__ = [
    'ToolSimulator', 'NmapSimulator', 'MetasploitSimulator',
    'HydraSimulator', 'JohnSimulator', 'SqlmapSimulator',
    'NiktoSimulator', 'GobusterSimulator', 'WPScanSimulator'
]
