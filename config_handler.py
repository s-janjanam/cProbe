import json
import os
import subprocess
import logging

class ConfigHandler:
    def __init__(self, config_path="/opt/nprobe/config/nprobe-config.json"):
        self.config_path = config_path
        self.logger = logging.getLogger("nprobe")
        self.load_config()

    def load_config(self):
        """Load configuration from JSON file"""
        try:
            with open(self.config_path, 'r') as f:
                self.config = json.load(f)
        except Exception as e:
            self.logger.error(f"Failed to load config: {str(e)}")
            self.config = {}

    def save_config(self):
        """Save current configuration to JSON file"""
        try:
            with open(self.config_path, 'w') as f:
                json.dump(self.config, f, indent=2)
        except Exception as e:
            self.logger.error(f"Failed to save config: {str(e)}")

    def update_config(self, section, key, value):
        """Update a specific configuration value"""
        if section not in self.config:
            self.config[section] = {}
        self.config[section][key] = value
        self.save_config()

    def get_config(self, section=None):
        """Get current configuration"""
        if section:
            return self.config.get(section, {})
        return self.config
