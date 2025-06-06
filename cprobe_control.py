import json
import os
import subprocess
import logging
from pathlib import Path
from typing import List, Dict, Optional, Union

class NProbeConstants:
    DEFAULT_TEMPLATE = "%IPV4_SRC_ADDR %IPV4_DST_ADDR %IN_BYTES %OUT_BYTES %IN_PKTS %OUT_PKTS"
    IDLE_TIMEOUT = 300  # 5 minutes
    LIFETIME_TIMEOUT = 1800  # 30 minutes 
    FLOW_VERSION = 9  # NetFlow v9
    DEFAULT_CPUS = {  # Example CPU affinity mapping
        0: "0",
        1: "1",
        2: "2",
        3: "3"
    }
    STATS_FILE_FORMAT = "/opt/nprobe/logs/nprobe-{}.stats"
    CONFIG_FILE_FORMAT = "/opt/nprobe/config/nprobe-{}.conf"
    LICENSE_PATH = "/etc/nprobe.license"
    ZC_LICENSE_DIR = "/etc/pf_ring/zc/"

class NProbeController:
    def __init__(self, instance_num: int = 0):
        self.logger = logging.getLogger("nprobe")
        self.instance_num = instance_num
        self.config_file = NProbeConstants.CONFIG_FILE_FORMAT.format(instance_num)
        self.stats_file = NProbeConstants.STATS_FILE_FORMAT.format(instance_num)
        self.process = None
        self._load_settings()

    def _load_settings(self):
        """Load settings from JSON configuration"""
        self.settings = {
            'interface': None,
            'target': 'none',
            'template': NProbeConstants.DEFAULT_TEMPLATE,
            'sample_rate': '1:1:1',  # pkt:collection:export
            'flow_version': NProbeConstants.FLOW_VERSION,
            'lifetime_timeout': NProbeConstants.LIFETIME_TIMEOUT,
            'idle_timeout': NProbeConstants.IDLE_TIMEOUT,
            'debug_level': 1,
            'cpu_affinity': NProbeConstants.DEFAULT_CPUS.get(self.instance_num, "0"),
            'aggregation': '1/1/1/1/0/0/0',  # VLAN/proto/IP/port/TOS/SCTP/exporter
            'license': None,
            'zc_licenses': []
        }
        
        try:
            config_path = Path("/opt/nprobe/config/nprobe-config.json")
            if config_path.exists():
                with open(config_path) as f:
                    saved_settings = json.load(f)
                    self.settings.update(saved_settings)
        except Exception as e:
            self.logger.error(f"Failed to load settings: {e}")

    def _save_settings(self):
        """Save current settings to JSON configuration"""
        try:
            config_path = Path("/opt/nprobe/config/nprobe-config.json")
            with open(config_path, 'w') as f:
                json.dump(self.settings, f, indent=2)
        except Exception as e:
            self.logger.error(f"Failed to save settings: {e}")

    def set_interface(self, interface: str):
        """Set capture interface"""
        self.settings['interface'] = interface
        self._save_settings()

    def set_target(self, target: str):
        """Set collector target(s)"""
        self.settings['target'] = target
        self._save_settings()

    def set_template(self, template: str):
        """Set flow template"""
        self.settings['template'] = template
        self._save_settings()

    def set_sample_rate(self, pkt_rate: int = 1, 
                       flow_collection_rate: int = 1,
                       flow_export_rate: int = 1):
        """Set sampling rates"""
        self.settings['sample_rate'] = f"{pkt_rate}:{flow_collection_rate}:{flow_export_rate}"
        self._save_settings()

    def set_timeouts(self, idle_timeout: int = None, lifetime_timeout: int = None):
        """Set flow timeouts"""
        if idle_timeout is not None:
            self.settings['idle_timeout'] = idle_timeout
        if lifetime_timeout is not None:
            self.settings['lifetime_timeout'] = lifetime_timeout
        self._save_settings()

    def set_flow_version(self, version: int):
        """Set NetFlow version (5, 9, or 10)"""
        if version in [5, 9, 10]:
            self.settings['flow_version'] = version
            self._save_settings()
        else:
            raise ValueError("Flow version must be 5, 9, or 10")

    def set_license(self, license_content: str):
        """Set nProbe license"""
        try:
            with open(NProbeConstants.LICENSE_PATH, 'w') as f:
                f.write(license_content)
            self.settings['license'] = license_content
            self._save_settings()
        except Exception as e:
            self.logger.error(f"Failed to set license: {e}")
            raise

    def add_zc_license(self, license_id: str, license_content: str):
        """Add a Zero Copy license"""
        try:
            # Create ZC license directory if it doesn't exist
            Path(NProbeConstants.ZC_LICENSE_DIR).mkdir(parents=True, exist_ok=True)
            
            # Write license file
            license_path = Path(NProbeConstants.ZC_LICENSE_DIR) / license_id
            with open(license_path, 'w') as f:
                f.write(license_content)

            # Update settings
            self.settings['zc_licenses'].append({
                'id': license_id,
                'license': license_content,
                'date': ''  # Will be populated when validated
            })
            self._save_settings()
        except Exception as e:
            self.logger.error(f"Failed to add ZC license: {e}")
            raise

    def write_configuration(self):
        """Write nProbe configuration file"""
        try:
            os.makedirs(os.path.dirname(self.config_file), exist_ok=True)
            with open(self.config_file, 'w') as fp:
                if self.settings['interface']:
                    fp.write(f"--interface={self.settings['interface']}\n")
                fp.write(f"--netflow-engine=0:{self.instance_num}\n")
                fp.write(f"--cpu-affinity={self.settings['cpu_affinity']}\n")
                fp.write(f"--verbose={self.settings['debug_level']}\n")
                
                if self.settings['target'] != 'none':
                    for target in self.settings['target'].split(','):
                        fp.write(f"--collector={target.strip()}\n")
                
                fp.write(f"--flow-templ=\"{self.settings['template']}\"\n")
                fp.write(f"--dump-stats={self.stats_file}\n")
                fp.write(f"--aggregation={self.settings['aggregation']}\n")
                fp.write(f"--sample-rate={self.settings['sample_rate']}\n")
                fp.write(f"--flow-version={self.settings['flow_version']}\n")
                fp.write(f"--lifetime-timeout={self.settings['lifetime_timeout']}\n")
                fp.write(f"--idle-timeout={self.settings['idle_timeout']}\n")

                # Add any custom advanced options
                if 'advanced_options' in self.settings:
                    for opt in self.settings['advanced_options']:
                        fp.write(f"{opt}\n")

            return True
        except Exception as e:
            self.logger.error(f"Failed to write configuration: {e}")
            return False

    def start(self) -> bool:
        """Start nProbe instance"""
        try:
            if not self.write_configuration():
                return False

            cmd = f"nprobe --config-file {self.config_file}"
            self.process = subprocess.Popen(cmd.split())
            self.logger.info(f"Started nProbe instance {self.instance_num}")
            return True
        except Exception as e:
            self.logger.error(f"Failed to start nProbe: {e}")
            return False

    def stop(self) -> bool:
        """Stop nProbe instance"""
        if self.process:
            try:
                self.process.terminate()
                self.process.wait(timeout=10)
                self.process = None
                self.logger.info(f"Stopped nProbe instance {self.instance_num}")
                return True
            except Exception as e:
                self.logger.error(f"Failed to stop nProbe: {e}")
                return False
        return True

    def restart(self) -> bool:
        """Restart nProbe instance"""
        self.stop()
        return self.start()

    def get_status(self) -> str:
        """Get nProbe instance status"""
        if not self.process:
            return "stopped"
        return "running" if self.process.poll() is None else "stopped"
