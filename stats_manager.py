# stats_manager.py
import threading
import time
import logging
from pathlib import Path
import re

class StatsManager:
    def __init__(self, controller, interval=5):
        """
        Initializes the Stats Manager.
        :param controller: The main NProbeController instance to get context.
        :param interval: The interval in seconds to poll for new stats.
        """
        self.logger = logging.getLogger("StatsManager")
        self.controller = controller
        self.interval = interval
        self.latest_stats = {}
        self._previous_pfring = {}
        self._previous_nprobe = {}
        self._lock = threading.Lock()
        self.is_running = False

    def _parse_proc_file(self, content):
        """Parses a generic key-value proc file."""
        stats = {}
        for line in content.splitlines():
            match = re.match(r'(\w+):\s*([\d,]+)', line)
            if match:
                key = match.group(1)
                value = int(match.group(2).replace(',', ''))
                stats[key] = value
        return stats

    def _collect_pfring_stats(self):
        """Collects and aggregates stats from /proc/net/pf_ring for all active ZC queues."""
        total_stats = {'packets_received': 0, 'bytes_received': 0, 'packets_dropped': 0}
        try:
            # PF_RING ZC creates stats files named after the process PID.
            # We will glob for all files associated with nprobe instances.
            base_dir = Path("/proc/net/pf_ring")
            for pid_file in Path(self.controller.PID_DIR).glob("nprobe-*.pid"):
                try:
                    pid = pid_file.read_text().strip()
                    # The stats file is typically named <pid>-<interface_name>.stats
                    # We glob as the exact name can vary slightly.
                    for stats_file in base_dir.glob(f"{pid}-*.stats"):
                        content = stats_file.read_text()
                        parsed = self._parse_proc_file(content)
                        total_stats['packets_received'] += parsed.get('Tot Pkts', 0)
                        total_stats['bytes_received'] += parsed.get('Tot Bytes', 0)
                        total_stats['packets_dropped'] += parsed.get('Dropped', 0)
                        break # Found stats for this PID, move to next
                except Exception:
                    continue # PID file might be stale, or stats file not ready
        except Exception as e:
            self.logger.warning(f"Could not read PF_RING stats: {e}")
        return total_stats

    def _collect_nprobe_stats(self):
        """Collects and aggregates stats from all nprobe instance stat files."""
        total_stats = {'flows_processed': 0, 'packets_processed': 0, 'flows_exported': 0, 'export_drops': 0, 'active_flows': 0}
        try:
            for i in range(self.controller.active_instances):
                stats_file = Path(f"/opt/nprobe/logs/nprobe-{i}.stats")
                if stats_file.exists():
                    content = stats_file.read_text()
                    parsed = self._parse_proc_file(content)
                    total_stats['flows_processed'] += parsed.get('Total_Flows', 0)
                    total_stats['packets_processed'] += parsed.get('Processed_Pkts', 0)
                    total_stats['flows_exported'] += parsed.get('Exported_Flows', 0)
                    total_stats['export_drops'] += parsed.get('Flows_Not_Exported', 0)
                    total_stats['active_flows'] += parsed.get('Active_Flows', 0)
        except Exception as e:
            self.logger.warning(f"Could not read nprobe stats files: {e}")
        return total_stats

    def _calculate_rates_and_update(self, current_pfring, current_nprobe, delta_t):
        """Calculates rates and updates the master stats dictionary."""
        # --- PF_RING Rates ---
        pps = (current_pfring['packets_received'] - self._previous_pfring.get('packets_received', 0)) / delta_t
        bps = ((current_pfring['bytes_received'] - self._previous_pfring.get('bytes_received', 0)) * 8) / delta_t
        gbps = bps / 1_000_000_000
        
        # --- nProbe Rates ---
        fps = (current_nprobe['flows_processed'] - self._previous_nprobe.get('flows_processed', 0)) / delta_t

        # --- Other important stats ---
        flow_cache_capacity = self.controller.config.get('nprobe', {}).get('flow_processing', {}).get('max_num_flows', 1)
        flow_cache_utilization = (current_nprobe['active_flows'] / flow_cache_capacity) * 100 if flow_cache_capacity else 0

        with self._lock:
            self.latest_stats = {
                "timestamp": time.time(),
                "pf_ring_stats": {
                    "packets_per_second": round(pps, 2),
                    "gbps_rate": round(gbps, 4),
                    "total_dropped_packets": current_pfring['packets_dropped'] # This is a key "processing drop" metric
                },
                "nprobe_stats": {
                    "flows_per_second": round(fps, 2),
                    "active_flows": current_nprobe['active_flows'],
                    "flow_cache_utilization_percent": round(flow_cache_utilization, 2),
                    "total_export_drops": current_nprobe['export_drops'] # "sending side" drops
                },
                "cumulative_totals": {
                    "total_packets_received": current_pfring['packets_received'],
                    "total_flows_processed": current_nprobe['flows_processed'],
                }
            }

        # Update previous state for next calculation
        self._previous_pfring = current_pfring
        self._previous_nprobe = current_nprobe

    def _collect_stats_loop(self):
        """The main loop for the background thread."""
        self.logger.info("Statistics collection thread started.")
        last_run = time.time()
        
        # Initial data capture
        self._previous_pfring = self._collect_pfring_stats()
        self._previous_nprobe = self._collect_nprobe_stats()
        time.sleep(self.interval)

        while self.is_running:
            try:
                now = time.time()
                delta_t = now - last_run
                if delta_t <= 0: # Avoid division by zero
                    time.sleep(self.interval)
                    continue
                last_run = now

                current_pfring = self._collect_pfring_stats()
                current_nprobe = self._collect_nprobe_stats()
                
                self._calculate_rates_and_update(current_pfring, current_nprobe, delta_t)

                time.sleep(self.interval)
            except Exception as e:
                self.logger.error(f"Error in stats collection loop: {e}")
                time.sleep(self.interval)

    def run_in_background(self):
        """Starts the background statistics collection thread."""
        if not self.is_running:
            self.is_running = True
            self.thread = threading.Thread(target=self._collect_stats_loop, daemon=True)
            self.thread.start()

    def get_latest_stats(self):
        """Returns the most recently collected stats. Thread-safe."""
        with self._lock:
            return self.latest_stats.copy()
