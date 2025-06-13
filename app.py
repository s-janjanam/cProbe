# app.py (Updated)
from flask import Flask, request, jsonify
from cprobe_control import NProbeController
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)
app = Flask(__name__)

# Use a single controller that manages the entire pool
controller = NProbeController()

@app.route('/api/status', methods=['GET'])
def get_status():
    """Get the running status of the nprobe instance pool."""
    return jsonify(controller.get_status())

@app.route('/api/config', methods=['GET'])
def get_config():
    """Get the current full configuration from config.json."""
    return jsonify(controller.config)

@app.route('/api/queues', methods=['POST'])
def set_queues():
    """Sets the number of hardware queues and restarts the nprobe pool."""
    data = request.get_json()
    if not data or 'count' not in data:
        return jsonify({"error": "Payload must contain 'count' (4, 8, or 12)"}), 400

    if controller.reconfigure_queues(data['count']):
        return jsonify({"message": f"System reconfigured for {data['count']} queues."})
    else:
        return jsonify({"error": "Failed to reconfigure queues."}), 500

@app.route('/api/restart', methods=['POST'])
def restart_pool():
    """Restarts all nprobe instances with the current queue configuration."""
    current_queues = controller.active_instances
    if controller.reconfigure_queues(current_queues):
         return jsonify({"message": f"nProbe pool restarted with {current_queues} instances."})
    else:
         return jsonify({"error": "Failed to restart nprobe pool"}), 500

@app.route('/api/stop', methods=['POST'])
def stop_pool():
    """Stops all running nprobe instances."""
    controller.stop_all_instances()
    return jsonify({"message": "All nprobe instances stopped."})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False)
