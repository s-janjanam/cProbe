# cprobe_control.py
import json
import os
import subprocess
import logging
from pathlib import Path
import time

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

class NProbeConstants:
    """Consolidated constants for nProbe configuration."""
    BASE_CONFIG_PATH = "/opt/nprobe/config/nprobe-config.json"
    CONFIG_FILE_FORMAT = "/opt/nprobe/config/nprobe-{}.conf"
    STATS_FILE_FORMAT = "/opt/nprobe/logs/nprobe-{}.stats"
    PID_FILE_FORMAT = "/var/run/nprobe-{}.pid"
    DEFAULT_TEMPLATE = "%IPV4_SRC_ADDR %IPV4_DST_ADDR %IN_BYTES %OUT_BYTES %IN_PKTS %OUT_PKTS"
    IDLE_TIMEOUT = 300
    LIFETIME_TIMEOUT = 1800
    FLOW_VERSION = 9
    DEBUG_LEVEL = 1

class NProbeController:
    def __init__(self, instance_num: int = 0):
        self.logger = logging.getLogger(f"NProbeController-{instance_num}")
        self.instance_num = instance_num
        self.config_file = NProbeConstants.CONFIG_FILE_FORMAT.format(instance_num)
        self.stats_file = NProbeConstants.STATS_FILE_FORMAT.format(instance_num)
        self.pid_file = NProbeConstants.PID_FILE_FORMAT.format(instance_num)
        self._load_settings()

    def _load_settings(self):
        """Load settings from JSON, applying defaults first."""
        self.settings = {
            'interface': 'zc:eth0',
            'target': 'none',
            'template': NProbeConstants.DEFAULT_TEMPLATE,
            'sample_rate': '1:1:1',
            'flow_version': NProbeConstants.FLOW_VERSION,
            'lifetime_timeout': NProbeConstants.LIFETIME_TIMEOUT,
            'idle_timeout': NProbeConstants.IDLE_TIMEOUT,
            'debug_level': NProbeConstants.DEBUG_LEVEL,
            'aggregation': '1/1/1/1/0/0/0',
            'advanced_options': []
        }
        try:
            config_path = Path(NProbeConstants.BASE_CONFIG_PATH)
            if config_path.exists():
                with open(config_path) as f:
                    self.settings.update(json.load(f))
                self.logger.info(f"Loaded configuration from {config_path}")
        except Exception as e:
            self.logger.error(f"Could not load settings from {NProbeConstants.BASE_CONFIG_PATH}: {e}")

    def _save_settings(self):
        """Save current settings to the base JSON configuration."""
        try:
            config_path = Path(NProbeConstants.BASE_CONFIG_PATH)
            config_path.parent.mkdir(parents=True, exist_ok=True)
            with open(config_path, 'w') as f:
                json.dump(self.settings, f, indent=4)
            self.logger.info(f"Saved configuration to {config_path}")
        except Exception as e:
            self.logger.error(f"Failed to save settings: {e}")

    def write_configuration(self) -> bool:
        """Write the nprobe .conf file from current settings."""
        self.logger.info(f"Writing configuration to {self.config_file}")
        try:
            Path(self.config_file).parent.mkdir(parents=True, exist_ok=True)
            with open(self.config_file, 'w') as fp:
                fp.write(f"--interface={self.settings['interface']}\n")
                fp.write(f"--pid-file={self.pid_file}\n")
                fp.write(f"--verbose={self.settings['debug_level']}\n")
                fp.write(f"--dump-stats={self.stats_file}\n")
                if self.settings['target'] != 'none':
                    for target in self.settings['target'].split(','):
                        fp.write(f"--collector={target.strip()}\n")
                fp.write(f"--flow-templ=\"{self.settings['template']}\"\n")
                fp.write(f"--aggregation={self.settings['aggregation']}\n")
                fp.write(f"--sample-rate={self.settings['sample_rate']}\n")
                fp.write(f"--flow-version={self.settings['flow_version']}\n")
                fp.write(f"--lifetime-timeout={self.settings['lifetime_timeout']}\n")
                fp.write(f"--idle-timeout={self.settings['idle_timeout']}\n")
                for opt in self.settings.get('advanced_options', []):
                    fp.write(f"{opt}\n")
            return True
        except Exception as e:
            self.logger.error(f"Failed to write configuration file: {e}")
            return False

    def _is_running(self) -> bool:
        """Check if the nprobe process is running via its PID file."""
        if not Path(self.pid_file).exists():
            return False
        try:
            with open(self.pid_file, 'r') as f:
                pid = int(f.read().strip())
            os.kill(pid, 0)
            return True
        except (IOError, ValueError, OSError):
            return False

    def start(self) -> bool:
        """Start nProbe using the start-nprobe.sh script."""
        if self._is_running():
            self.logger.warning(f"nProbe instance {self.instance_num} is already running.")
            return True
        if not self.write_configuration():
            return False
        try:
            cmd = f"/opt/nprobe/scripts/start-nprobe.sh --config-file {self.config_file}"
            subprocess.Popen(cmd.split())
            self.logger.info(f"Start command issued for nProbe instance {self.instance_num}.")
            return True
        except Exception as e:
            self.logger.error(f"Failed to start nProbe: {e}")
            return False

    def stop(self) -> bool:
        """Stop the nProbe instance by killing the process from the PID file."""
        if not self._is_running():
            self.logger.warning(f"nProbe instance {self.instance_num} is not running.")
            return True
        try:
            with open(self.pid_file, 'r') as f:
                pid = int(f.read().strip())
            self.logger.info(f"Stopping nProbe instance {self.instance_num} with PID {pid}...")
            os.kill(pid, 15)  # SIGTERM
            Path(self.pid_file).unlink(missing_ok=True)
            return True
        except Exception as e:
            self.logger.error(f"Failed to stop nProbe: {e}")
            return False

    def restart(self) -> bool:
        """Restart the nProbe instance."""
        self.logger.info(f"Restarting nProbe instance {self.instance_num}...")
        if self._is_running():
            self.stop()
            time.sleep(2)
        return self.start()

    def get_status(self) -> str:
        """Get nProbe instance status."""
        return "running" if self._is_running() else "stopped"
