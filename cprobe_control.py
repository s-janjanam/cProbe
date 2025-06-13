# cprobe_control.py (Rewritten)
import json
import os
import subprocess
import logging
import time
from pathlib import Path

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

class NProbeController:
    CONFIG_PATH = "/opt/nprobe/config/config.json"
    PID_DIR = "/var/run"

    def __init__(self):
        self.logger = logging.getLogger("NProbeController")
        self.config = self._load_config()
        self.active_instances = self.config.get('nprobe', {}).get('capture', {}).get('num_threads', 1)

    def _load_config(self):
        """Loads the entire config.json file."""
        self.logger.info(f"Loading configuration from {self.CONFIG_PATH}")
        try:
            with open(self.CONFIG_PATH, 'r') as f:
                return json.load(f)
        except FileNotFoundError:
            self.logger.error("config.json not found!")
            return {}
        except json.JSONDecodeError:
            self.logger.error("Error decoding config.json!")
            return {}

    def _save_config(self):
        """Saves the current config back to the file."""
        self.logger.info(f"Saving configuration to {self.CONFIG_PATH}")
        try:
            with open(self.CONFIG_PATH, 'w') as f:
                json.dump(self.config, f, indent=2)
        except Exception as e:
            self.logger.error(f"Failed to save config: {e}")

    def _run_command(self, cmd):
        """Helper to run and log shell commands."""
        self.logger.info(f"Executing: {cmd}")
        try:
            result = subprocess.run(cmd, shell=True, check=True, capture_output=True, text=True)
            if result.stdout: self.logger.info(result.stdout)
            return True
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Command failed: {cmd}\n{e.stderr}")
            return False

    def apply_system_tuning(self):
        """Applies system-level tuning from config.json."""
        self.logger.info("Applying system tuning...")
        env_config = self.config.get('environment', {})
        ofed_config = env_config.get('mellanox_ofed', {})
        sys_config = env_config.get('system', {})

        if ofed_config.get('configure_hugepages'):
            count = ofed_config.get('hugepages_count', 1024)
            self._run_command(f"echo {count} > /proc/sys/vm/nr_hugepages")

        if sys_config.get('set_cpu_governor') == 'performance':
            self._run_command("for file in /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor; do echo 'performance' > $file; done")

    def stop_all_instances(self):
        """Stops all running nprobe instances based on PID files."""
        self.logger.info("Stopping all nprobe instances...")
        for pid_file in Path(self.PID_DIR).glob("nprobe-*.pid"):
            try:
                pid = int(pid_file.read_text().strip())
                self.logger.info(f"Stopping process with PID {pid} from {pid_file.name}")
                os.kill(pid, 15)  # SIGTERM
            except (ValueError, OSError) as e:
                self.logger.warning(f"Could not stop process from {pid_file.name}: {e}")
            finally:
                pid_file.unlink()
        time.sleep(2)  # Grace period for processes to die

    def start_all_instances(self):
        """Starts nprobe instances based on current configuration."""
        nprobe_config = self.config.get('nprobe', {})
        if not nprobe_config:
            self.logger.error("'nprobe' section missing in config.json. Cannot start.")
            return

        main_interface = nprobe_config.get('capture', {}).get('interface', 'eth0')
        cpu_affinity_map = nprobe_config.get('performance', {}).get('cpu_affinity', {})

        self.logger.info(f"Starting {self.active_instances} nprobe instances for interface {main_interface}...")

        for i in range(self.active_instances):
            instance_conf_path = f"/opt/nprobe/config/nprobe-{i}.conf"
            instance_pid_path = f"{self.PID_DIR}/nprobe-{i}.pid"
            
            # Use ZC syntax for multi-queue
            instance_interface = f"zc:{main_interface}@{i}"
            # Pin to CPU core from map, or fall back to instance number
            instance_cpu = cpu_affinity_map.get(str(i), i)
            
            with open(instance_conf_path, 'w') as f:
                # Core instance settings
                f.write(f"--interface={instance_interface}\n")
                f.write(f"--pid-file={instance_pid_path}\n")
                f.write(f"--cpu-affinity={instance_cpu}\n")

                # Add other settings from config.json
                # This is a simplified example; a real implementation would iterate the JSON
                f.write(f"-v {nprobe_config.get('general', {}).get('verbose_level', 1)}\n")
                collector = nprobe_config.get('flow_export', {})
                f.write(f"-n {collector.get('collector_ip')}:{collector.get('collector_port')}\n")
                if nprobe_config.get('templates', {}).get('use_custom_template', False):
                    f.write(f"-T \"{nprobe_config.get('templates', {}).get('custom_template')}\"\n")
                f.write(f"-t {nprobe_config.get('flow_export', {}).get('inactive_timeout', 15)}\n")
                f.write(f"-d {nprobe_config.get('flow_export', {}).get('active_timeout', 300)}\n")

            # Launch this instance using the helper script
            self._run_command(f"/opt/nprobe/scripts/start-nprobe.sh --config-file {instance_conf_path}")

    def reconfigure_queues(self, queue_count: int):
        """The main logic: stop, set hardware queues, update config, and start."""
        if queue_count not in [4, 8, 12]:
             self.logger.error(f"Invalid queue count: {queue_count}. Must be 4, 8, or 12.")
             return False

        # 1. Stop all current instances
        self.stop_all_instances()

        # 2. Set the hardware queue count on the main interface
        main_interface = self.config.get('nprobe', {}).get('capture', {}).get('interface')
        if not main_interface:
            self.logger.error("No capture interface defined in config.json!")
            return False
        
        self.logger.info(f"Setting NIC {main_interface} to {queue_count} combined queues...")
        if not self._run_command(f"ethtool -L {main_interface} combined {queue_count}"):
             self.logger.error("Failed to set hardware queues via ethtool. Aborting.")
             return False
        
        # 3. Update the configuration state and save it
        self.active_instances = queue_count
        self.config['nprobe']['capture']['num_threads'] = queue_count
        self._save_config()

        # 4. Start the new pool of instances
        self.start_all_instances()
        return True

    def get_status(self):
        """Returns the status of the nprobe instance pool."""
        running_pids = list(Path(self.PID_DIR).glob("nprobe-*.pid"))
        return {
            "configured_instances": self.active_instances,
            "running_instances": len(running_pids),
            "status": "running" if len(running_pids) > 0 else "stopped",
            "pids": [p.name for p in running_pids]
        }
