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

    # stats_manager.py -> _collect_pfring_stats (Updated)

    def _collect_pfring_stats(self):
        """
        Collects stats from /proc/net/pf_ring for each active ZC queue.
        Returns a dictionary of per-queue stats, e.g., {'0': {'packets': X, ...}, '1': ...}
        """
        per_queue_stats = {}
        try:
            base_dir = Path("/proc/net/pf_ring")
            # Find stats files based on running PIDs
            for pid_file in Path(self.controller.PID_DIR).glob("nprobe-*.pid"):
                try:
                    pid = pid_file.read_text().strip()
                    for stats_file in base_dir.glob(f"{pid}-*.stats"):
                        # Extract queue ID from filename like '12345-zc:eth0@1.stats'
                        match = re.search(r'@(\d+)', stats_file.name)
                        if not match:
                            continue
                        
                        queue_id = match.group(1)
                        content = stats_file.read_text()
                        parsed = self._parse_proc_file(content)
                        
                        per_queue_stats[queue_id] = {
                            'packets_received': parsed.get('Tot Pkts', 0),
                            'bytes_received': parsed.get('Tot Bytes', 0),
                            'packets_dropped': parsed.get('Dropped', 0)
                        }
                        # Found stats for this PID, move to the next PID file
                        break 
                except Exception:
                    continue
        except Exception as e:
            self.logger.warning(f"Could not read PF_RING stats: {e}")
        return per_queue_stats

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

    # stats_manager.py -> _calculate_rates_and_update (Updated)

    def _calculate_rates_and_update(self, current_pfring, current_nprobe, delta_t):
        """Calculates rates and updates the master stats dictionary."""
        
        # --- Aggregate PF_RING totals for overall rates ---
        total_current_pkts = sum(q['packets_received'] for q in current_pfring.values())
        total_current_bytes = sum(q['bytes_received'] for q in current_pfring.values())
        total_previous_pkts = sum(q.get('packets_received', 0) for q in self._previous_pfring.values())
        total_previous_bytes = sum(q.get('bytes_received', 0) for q in self._previous_pfring.values())
        
        pps = (total_current_pkts - total_previous_pkts) / delta_t
        gbps = ((total_current_bytes - total_previous_bytes) * 8) / (delta_t * 1_000_000_000)
        total_dropped = sum(q['packets_dropped'] for q in current_pfring.values())

        # --- Calculate RX Queue Distribution ---
        rx_queue_distribution = {}
        delta_total_pkts = total_current_pkts - total_previous_pkts
        
        if delta_total_pkts > 0:
            for q_id, q_stats in current_pfring.items():
                prev_q_pkts = self._previous_pfring.get(q_id, {}).get('packets_received', 0)
                delta_q_pkts = q_stats['packets_received'] - prev_q_pkts
                percentage = (delta_q_pkts / delta_total_pkts) * 100
                rx_queue_distribution[q_id] = {
                    "usage_percent": round(percentage, 2),
                    "dropped_packets": q_stats['packets_dropped'] # Per-queue drop count
                }

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
                    "total_dropped_packets": total_dropped
                },
                "rx_queue_distribution": rx_queue_distribution, # <-- NEWLY ADDED
                "nprobe_stats": {
                    "flows_per_second": round(fps, 2),
                    "active_flows": current_nprobe['active_flows'],
                    "flow_cache_utilization_percent": round(flow_cache_utilization, 2),
                    "total_export_drops": current_nprobe['export_drops']
                },
                "cumulative_totals": {
                    "total_packets_received": total_current_pkts,
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
