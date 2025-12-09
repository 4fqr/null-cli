"""Base class for all tool simulators"""
from abc import ABC, abstractmethod
from typing import Any, Dict, List
import time
import random

from ..config import ConfigManager
from ..ui import console, print_simulation_header, print_educational_info


class ToolSimulator(ABC):
    """Abstract base class for security tool simulators"""
    
    def __init__(self, tool_name: str, educational: bool = False):
        self.tool_name = tool_name
        self.educational = educational
        self.config = ConfigManager()
        self.fake_data = self._load_fake_data()
        
    @abstractmethod
    def run(self, args: tuple):
        """Execute the simulation with given arguments"""
        pass
        
    def _load_fake_data(self) -> Dict[str, Any]:
        """Load appropriate fake data based on tool"""
        return {}
        
    def _log_simulation(self, command: str):
        """Log simulation activity"""
        self.config.log_command(self.tool_name, command)
        
    def _simulate_delay(self, min_seconds: float = 0.1, max_seconds: float = 2.0):
        """Simulate processing time for realistic output"""
        delay = random.uniform(min_seconds, max_seconds)
        time.sleep(delay)
        
    def _show_simulation_header(self):
        """Display simulation mode header"""
        if self.config.get('show_simulation_watermark', True):
            print_simulation_header(self.tool_name)
            
    def _show_educational_info(self, title: str, description: str, impact: str):
        """Display educational information if enabled"""
        if self.educational:
            print_educational_info(title, description, impact)
            
    def _format_timestamp(self) -> str:
        """Generate realistic timestamp"""
        from datetime import datetime
        return datetime.now().strftime("%Y-%m-%d %H:%M %Z")
        
    def _simulate_progress(self, stages: List[str], delay_per_stage: float = 0.5):
        """Simulate multi-stage progress"""
        for stage in stages:
            console.print(f"[cyan][*][/cyan] {stage}")
            time.sleep(delay_per_stage)
