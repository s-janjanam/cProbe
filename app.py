# api.py
from flask import Flask, request, jsonify
from cprobe_control import NProbeController
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

app = Flask(__name__)
# The controller for nProbe instance 0
controller = NProbeController(instance_num=0)

@app.route('/api/status', methods=['GET'])
def get_status():
    """Get the running status of the nprobe instance."""
    status = controller.get_status()
    return jsonify({"status": status})

@app.route('/api/config', methods=['GET'])
def get_config():
    """Get the current nprobe configuration."""
    return jsonify(controller.settings)

@app.route('/api/config', methods=['POST'])
def set_config():
    """Update nprobe configuration."""
    new_config = request.get_json()
    if not new_config:
        return jsonify({"error": "Invalid JSON payload"}), 400

    try:
        # Update settings in the controller
        for key, value in new_config.items():
            if key in controller.settings:
                controller.settings[key] = value

        controller._save_settings()
        controller.write_configuration()

        logger.info("Configuration updated. A restart is required for changes to take effect.")
        return jsonify({
            "message": "Configuration updated successfully. Restart nprobe to apply changes.",
            "new_config": controller.settings
        })
    except Exception as e:
        logger.error(f"Error updating configuration: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/start', methods=['POST'])
def start_nprobe():
    """Start the nprobe instance."""
    if controller.get_status() == 'running':
        return jsonify({"message": "nprobe is already running"}), 400
    if controller.start():
        return jsonify({"message": "nprobe started successfully"})
    else:
        return jsonify({"error": "Failed to start nprobe"}), 500

@app.route('/api/stop', methods=['POST'])
def stop_nprobe():
    """Stop the nprobe instance."""
    if controller.stop():
        return jsonify({"message": "nprobe stopped successfully"})
    else:
        return jsonify({"error": "Failed to stop nprobe"}), 500

@app.route('/api/restart', methods=['POST'])
def restart_nprobe():
    """Restart the nprobe instance."""
    if controller.restart():
        return jsonify({"message": "nprobe restarted successfully"})
    else:
        return jsonify({"error": "Failed to restart nprobe"}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False)
