"""Configuration manager for null-cli"""
import json
import os
from pathlib import Path
from typing import Any, Dict


class ConfigManager:
    """Manages configuration and history for null-cli"""
    
    def __init__(self):
        self.config_dir = Path.home() / ".null-cli"
        self.config_file = self.config_dir / "config.json"
        self.history_file = self.config_dir / "history.log"
        self._ensure_config_dir()
        
    def _ensure_config_dir(self):
        """Create config directory if it doesn't exist"""
        self.config_dir.mkdir(exist_ok=True)
        if not self.config_file.exists():
            self._write_default_config()
            
    def _write_default_config(self):
        """Write default configuration"""
        default_config = {
            "version": "1.0.0",
            "first_run": True,
            "favorite_tool": None,
            "paranoia_mode": False,
            "educational_mode": False,
            "show_simulation_watermark": True,
        }
        with open(self.config_file, 'w') as f:
            json.dump(default_config, f, indent=2)
            
    def get(self, key: str, default: Any = None) -> Any:
        """Get configuration value"""
        try:
            with open(self.config_file, 'r') as f:
                config = json.load(f)
                return config.get(key, default)
        except (FileNotFoundError, json.JSONDecodeError):
            return default
            
    def set(self, key: str, value: Any):
        """Set configuration value"""
        try:
            with open(self.config_file, 'r') as f:
                config = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            config = {}
            
        config[key] = value
        
        with open(self.config_file, 'w') as f:
            json.dump(config, f, indent=2)
            
    def log_command(self, tool: str, command: str):
        """Log simulation activity"""
        import datetime
        timestamp = datetime.datetime.now().isoformat()
        log_entry = f"[{timestamp}] {tool}: {command}\n"
        
        with open(self.history_file, 'a') as f:
            f.write(log_entry)
            
    def get_history(self, limit: int = 50) -> list:
        """Get recent command history"""
        if not self.history_file.exists():
            return []
            
        with open(self.history_file, 'r') as f:
            lines = f.readlines()
            return lines[-limit:]
