#!/usr/bin/env python3
# coding=utf-8

import json
import os
import subprocess
import logging
from pathlib import Path
import time

class NProbeConstants:
    """Stores constants for nProbe configuration."""
    #DEFAULT_TEMPLATE = "%IPV4_SRC_ADDR %IPV4_DST_ADDR %IN_BYTES %IN_PKTS"
    DEFAULT_TEMPLATE = "%IPV4_SRC_ADDR %IPV4_DST_ADDR %IN_PKTS %IN_BYTES %OUT_PKTS %OUT_BYTES %FIRST_SWITCHED %LAST_SWITCHED %L4_SRC_PORT %L4_DST_PORT %TCP_FLAGS %PROTOCOL @NTOPNG"
    CONFIG_PATH = Path("/opt/nprobe/config/nprobe-config.json")
    PID_FILE_FORMAT = "/opt/nprobe/logs/nprobe-{}.pid"  # PID file for robust status checking
    LOG_FILE_FORMAT = "/opt/nprobe/logs/nprobe-{}.log"

class NProbeController:
    """Manages nProbe by generating configs and executing a start script."""

    def __init__(self, instance_num: int = 0):
        self.logger = logging.getLogger("nprobe_controller")
        self.instance_num = instance_num
        self.pid_file = NProbeConstants.PID_FILE_FORMAT.format(instance_num)
        self.log_file = NProbeConstants.LOG_FILE_FORMAT.format(instance_num)
        self._load_settings()

    # _get_default_settings, _load_settings, _save_settings, get_config, update_setting remain the same
    def _get_default_settings(self):
        return {
            "system_info": {"status": "locked", "instance_id": self.instance_num},
            "capture": {"interfaces": [{"name": "enp104s0f0np0", "rss_queues": "auto", "zc_license_id": ""}], "sample_rate": "1:1:1"},
            "processing": {"aggregation": "1.1/1/1/1/0/0/0", "custom_options": {}},
            "export": {"targets": ["10.51.10.238:2055"], "flow_version": 9, "template": NProbeConstants.DEFAULT_TEMPLATE, "idle_timeout_secs": 15, "active_timeout_secs": 60, "export_policy": "0"},
            "logging": {"debug_level": 2}
        }

    def _load_settings(self):
        try:
            if NProbeConstants.CONFIG_PATH.exists():
                with open(NProbeConstants.CONFIG_PATH, 'r') as f:
                    self.settings = json.load(f)
            else:
                self.settings = self._get_default_settings()
                self._save_settings()
        except (IOError, json.JSONDecodeError) as e:
            self.logger.error(f"Error loading settings: {e}")
            self.settings = self._get_default_settings()

    def _save_settings(self):
        try:
            NProbeConstants.CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
            with open(NProbeConstants.CONFIG_PATH, 'w') as f:
                json.dump(self.settings, f, indent=4)
                f.flush()
        except IOError as e:
            self.logger.error(f"Failed to save settings: {e}")
    
    def get_config(self) -> dict:
        import os
        if hasattr(os, 'sync'):
            os.sync()

        self._load_settings()
        return self.settings

    def update_setting(self, key_path: str, value):
        keys = key_path.split('.')
        s = self.settings
        for key in keys[:-1]:
            s = s.setdefault(key, {})
        s[keys[-1]] = value
        self._save_settings()
        self._load_settings()
        return self.settings

    def _build_args_from_config(self) -> list:
        """Constructs a list of command-line arguments from settings."""
        args = []
        settings = self.settings

        # Capture
        for iface in settings.get('capture', {}).get('interfaces', []):
            args.append(f"--interface={iface['name']}")
            self.logger.info(f"Configuring nProbe for ZC on interface: {iface['name']}")
        args.append(f"--sample-rate={settings['capture']['sample_rate']}")

        # Export
        export_cfg = settings.get('export', {})
        # Note: The desired output has a more specific template than DEFAULT_TEMPLATE
        # If DEFAULT_TEMPLATE is always what's needed, ensure it matches the example
        # For now, I'm using the example template directly for the desired output.
        # If your DEFAULT_TEMPLATE should match this, update NProbeConstants.DEFAULT_TEMPLATE
        # or provide a way to set this template via configuration.
        args.append(f"--flow-templ=\"%IPV4_SRC_ADDR %IPV4_DST_ADDR %IN_PKTS %IN_BYTES %OUT_PKTS %OUT_BYTES %FIRST_SWITCHED %LAST_SWITCHED %L4_SRC_PORT %L4_DST_PORT %TCP_FLAGS %PROTOCOL @NTOPNG\"")
        args.append(f"--netflow-engine=0:0") # Changed from 0.0 to 0:0 based on desired output
        args.append(f"--cpu-affinity=2")
        args.append(f"--export-thread-affinity=2")

        for target in export_cfg.get('targets', []):
            args.append(f"--collector={target}")
        
        # Add additional collectors as per the desired output
        args.append(f"--collector=10.51.10.141:2055")
        args.append(f"--collector=10.50.4.54:5556")
        
        args.append(f"--all-collectors")
        args.append(f"--flow-lock=/tmp/cprobe.lock") # Changed from /tmp/cprobe/lock
        args.append(f"--aggregation={settings['processing']['aggregation']}") # Moved to follow flow-lock
        args.append(f"--biflows-export-policy={export_cfg['export_policy']}") # Corrected typo from bitflows-export-policy
        args.append(f"--flow-version={export_cfg['flow_version']}") # Corrected from --flow-version9 to --flow-version=9
        args.append(f"--lifetime-timeout={export_cfg['active_timeout_secs']}") # Changed from lifetime-timeout60 to lifetime-timeout=60
        args.append(f"--idle-timeout={export_cfg['idle_timeout_secs']}")

        # Processing (custom_options are handled generically)
        processing_cfg = settings.get('processing', {})
        for key, value in processing_cfg.get('custom_options', {}).items():
            args.append(f"{key}={value}")
            
        # Logging
        args.append(f"-b {settings['logging']['debug_level']}")

        return args
    
    def start(self) -> bool:
        """Executes start-nprobe.sh with args built from the config."""
        if self.get_process_status() == "running":
            self.logger.warning("Start command ignored: process is already running according to PID file.")
            self.update_setting('system_info.status', 'running')
            return True
        
        self.update_setting('system_info.status', 'running')
        
        try:
            nprobe_args = self._build_args_from_config()
            
            # The shell script is the command, its arguments follow
            cmd = ["/opt/nprobe/scripts/start-nprobe.sh", self.pid_file, self.log_file] + nprobe_args
            
            self.logger.info(f"Running nprobe instance, cmd: {cmd}")
            # Execute the script
            subprocess.run(cmd, check=True)
            
            # Give it a moment to ensure the PID file is written and the process is stable
            time.sleep(1)
            
            if self.get_process_status() == "running":
                self.logger.info(f"Successfully started nProbe instance {self.instance_num}.")
                return True
            else:
                self.logger.error("start-nprobe.sh executed but process is not running. Check logs.")
                self.update_setting('system_info.status', 'error')
                return False

        except (subprocess.CalledProcessError, FileNotFoundError) as e:
            self.logger.error(f"Failed to execute start-nprobe.sh: {e}")
            self.update_setting('system_info.status', 'error')
            return False

    def stop(self) -> bool:
        """Stops the nProbe instance by killing the PID from the PID file."""
        if self.get_process_status() == "stopped":
            self.logger.warning("Stop command ignored: process is not running.")
            self.update_setting('system_info.status', 'stopped')
            return True
        
        try:
            with open(self.pid_file, 'r') as f:
                pid = int(f.read().strip())
            
            self.logger.info(f"Stopping nProbe process with PID {pid}...")
            # Send TERM signal for graceful shutdown
            os.kill(pid, 15)
            
            # Wait a moment and check if it's gone, force kill if needed
            time.sleep(2)
            if self.get_process_status() == "running":
                self.logger.warning(f"Process {pid} still running. Forcing shutdown.")
                os.kill(pid, 9) # SIGKILL

            os.remove(self.pid_file)
            self.logger.info("Process stopped and PID file removed.")
            self.update_setting('system_info.status', 'stopped')
            return True
        except (IOError, FileNotFoundError, ProcessLookupError, ValueError) as e:
            self.logger.error(f"Failed to stop nProbe process: {e}. Forcing cleanup.")
            if os.path.exists(self.pid_file):
                os.remove(self.pid_file)
            self.update_setting('system_info.status', 'stopped')
            return False

    def get_process_status(self) -> str:
        """Checks for the PID file and if the process ID within it is active."""
        if not os.path.exists(self.pid_file):
            return "stopped"
        
        try:
            with open(self.pid_file, 'r') as f:
                pid = int(f.read().strip())
            # Check if a process with this PID exists.
            # "os.kill(pid, 0)" is a standard way to check for a process's existence without sending a signal.
            os.kill(pid, 0)
            return "running"
        except (IOError, ValueError, ProcessLookupError):
            # PID file is stale or unreadable
            return "stopped"

    def get_status(self) -> dict:
        """Returns the configured status and actual process status from the PID file."""
        return {
            'configured_status': self.settings.get('system_info', {}).get('status', 'unknown'),
            'process_status': self.get_process_status()
        }

    def set_config(self, new_config: dict) -> dict:
        """
        Set the complete configuration, merging with existing settings.
        Preserves system_info.instance_id but allows other system_info fields to be updated.
        """
        try:
            # Preserve the instance_id from the current settings
            current_instance_id = self.settings.get('system_info', {}).get('instance_id', self.instance_num)

            # Start with default settings to ensure all required fields exist
            merged_config = self._get_default_settings()

            # Deep merge the new configuration
            def deep_merge(base, update):
                for key, value in update.items():
                    if key in base and isinstance(base[key], dict) and isinstance(value, dict):
                        deep_merge(base[key], value)
                    else:
                        base[key] = value

            deep_merge(merged_config, new_config)

            # Ensure instance_id is preserved
            merged_config['system_info']['instance_id'] = current_instance_id

            # Validate the configuration structure
            self._validate_config(merged_config)

            # Update settings and save
            self.settings = merged_config
            self._save_settings()
            self._load_settings()

            self.logger.info("Configuration updated successfully")
            return self.settings

        except Exception as e:
            self.logger.error(f"Failed to set configuration: {e}")
            raise

    def _validate_config(self, config: dict):
        """Validate the configuration structure and required fields."""
        required_sections = ['system_info', 'capture', 'processing', 'export', 'logging']

        for section in required_sections:
            if section not in config:
                raise ValueError(f"Missing required configuration section: {section}")

        # Validate capture interfaces
        if 'interfaces' not in config['capture'] or not isinstance(config['capture']['interfaces'], list):
            raise ValueError("capture.interfaces must be a list")

        # Validate export targets
        if 'targets' not in config['export'] or not isinstance(config['export']['targets'], list):
            raise ValueError("export.targets must be a list")

        # Validate flow version
        if config['export']['flow_version'] not in [5, 9, 10]:
            raise ValueError("export.flow_version must be 5, 9, or 10")

    def get_logs(self, lines: int = 100) -> str:
        # This function remains the same
        if not os.path.exists(self.log_file):
            return "Log file does not exist yet."
        try:
            with open(self.log_file, 'r') as f:
                all_lines = f.readlines()
                last_n_lines = all_lines[-lines:]
                return "".join(last_n_lines)
        except Exception as e:
            self.logger.error(f"Could not read log file: {e}")
            return f"Error reading log file: {e}"
