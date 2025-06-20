#!/usr/bin/env python3
# coding=utf-8

"""
A comprehensive Flask API to control nProbe instances.
Provides granular configuration endpoints and state management.
"""

import logging
import gc
import os
from flask import Flask, jsonify, request, send_from_directory, send_file
from cprobe_control import NProbeController

# --- Setup ---
app = Flask(__name__)
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger("nprobe_api")

try:
    controller = NProbeController(instance_num=0)
except Exception as e:
    logger.critical(f"Failed to initialize NProbeController: {e}")
    controller = None

# --- Helper for API Responses ---
def api_response(success, data=None, message="", status_code=200):
    """Generates a consistent JSON response."""
    response = {"success": success}
    if data:
        response['data'] = data
    if message:
        response['message'] = message
    return jsonify(response), status_code

# --- UI Serving Endpoints ---

@app.route('/')
def serve_ui():
    """Serve the main UI page."""
    static_path = '/opt/nprobe/static'
    if os.path.exists(os.path.join(static_path, 'ui.html')):
        return send_file(os.path.join(static_path, 'ui.html'))
    else:
        return jsonify({"error": "UI not found"}), 404

@app.route('/ui')
def serve_ui_alt():
    """Alternative route for the UI."""
    return serve_ui()

@app.route('/static/<path:filename>')
def serve_static(filename):
    """Serve static files."""
    static_path = '/opt/nprobe/static'
    return send_from_directory(static_path, filename)

# --- State and Control Endpoints ---

@app.route('/api/status', methods=['GET'])
def get_status():
    """Get the configured and actual status of the nProbe instance."""
    if not controller: return api_response(False, message="Controller not initialized", status_code=500)
    return api_response(True, controller.get_status())

@app.route('/api/start', methods=['POST'])
def start_nprobe():
    """Starts the nProbe instance."""
    if not controller: return api_response(False, message="Controller not initialized", status_code=500)
    if controller.start():
        return api_response(True, message="nProbe start command issued.")
    return api_response(False, message="Failed to start nProbe.", status_code=500)

@app.route('/api/stop', methods=['POST'])
def stop_nprobe():
    """Stops the nProbe instance."""
    if not controller: return api_response(False, message="Controller not initialized", status_code=500)
    if controller.stop():
        return api_response(True, message="nProbe stop command issued.")
    return api_response(False, message="Failed to stop nProbe.", status_code=500)

@app.route('/api/restart', methods=['POST'])
def restart_nprobe():
    """Restarts the nProbe instance."""
    if not controller: return api_response(False, message="Controller not initialized", status_code=500)
    controller.stop()
    if controller.start():
        return api_response(True, message="nProbe restart command issued.")
    return api_response(False, message="Failed to restart nProbe.", status_code=500)

@app.route('/api/restart_system', methods=['POST'])
def restart_system():
    """Refreshes the controller with a new instance of NProbeController, clearing all memory."""
    global controller
    
    try:
        # Stop the current instance if it exists and is running
        if controller:
            logger.info("Stopping current nProbe instance before system restart")
            controller.stop()
            
            # Clear the controller reference
            old_controller = controller
            controller = None
            
            # Force garbage collection to clean up memory
            del old_controller
            gc.collect()
            logger.info("Old controller instance cleaned up")
        
        # Create a new controller instance
        logger.info("Creating new NProbeController instance")
        controller = NProbeController(instance_num=0)
        
        return api_response(True, message="System restarted successfully with fresh controller instance.")
        
    except Exception as e:
        logger.error(f"Failed to restart system: {e}")
        return api_response(False, message=f"Failed to restart system: {e}", status_code=500)

# --- Configuration Endpoints ---

@app.route('/api/config', methods=['GET'])
def get_config():
    """Get the full nProbe configuration."""
    if not controller: return api_response(False, message="Controller not initialized", status_code=500)
    return api_response(True, controller.get_config())

@app.route('/api/config', methods=['POST'])
def set_config():
    """Set the complete nProbe configuration. Ex: {"capture": {...}, "export": {...}, ...}"""
    if not controller: return api_response(False, message="Controller not initialized", status_code=500)
    data = request.json
    if not data or not isinstance(data, dict):
        return api_response(False, message="Request body must be a JSON object with configuration data.", status_code=400)
    
    try:
        updated_config = controller.set_config(data)
        return api_response(True, updated_config, "Configuration updated successfully.")
    except Exception as e:
        return api_response(False, message=f"Error updating configuration: {e}", status_code=500)

@app.route('/api/logs', methods=['GET'])
def get_logs():
    """Get the nProbe instance logs. Optional query parameter 'lines' to specify number of lines (default: 100)."""
    if not controller: return api_response(False, message="Controller not initialized", status_code=500)
    
    lines = request.args.get('lines', default=100, type=int)
    if lines <= 0:
        return api_response(False, message="Lines parameter must be a positive integer.", status_code=400)
    
    try:
        logs = controller.get_logs(lines)
        return api_response(True, {"logs": logs, "lines_requested": lines}, "Logs retrieved successfully.")
    except Exception as e:
        return api_response(False, message=f"Error retrieving logs: {e}", status_code=500)

@app.route('/api/config/interfaces', methods=['POST'])
def set_interfaces():
    """
    Sets the list of capture interfaces.
    The body should be a JSON object with an "interfaces" key, which is a list.
    e.g., {"interfaces": [{"name": "eth0"}, {"name": "eth1", "rss_queues": "1,2,3,4"}]}
    """
    if not controller: return api_response(False, message="Controller not initialized", status_code=500)
    data = request.json
    if not data or 'interfaces' not in data or not isinstance(data['interfaces'], list):
        return api_response(False, message="Request body must be a JSON object with an 'interfaces' list.", status_code=400)

    updated_config = controller.update_setting('capture.interfaces', data['interfaces'])
    return api_response(True, updated_config, "Capture interfaces updated.")

@app.route('/api/config/targets', methods=['POST'])
def set_targets():
    """Set the list of collector targets. e.g., {"targets": ["127.0.0.1:2055"]}"""
    if not controller: return api_response(False, message="Controller not initialized", status_code=500)
    data = request.json
    if not data or 'targets' not in data or not isinstance(data['targets'], list):
        return api_response(False, message="Request body must be a JSON object with a 'targets' list.", status_code=400)

    updated_config = controller.update_setting('export.targets', data['targets'])
    return api_response(True, updated_config, "Export targets updated.")

@app.route('/api/config/timeouts', methods=['POST'])
def set_timeouts():
    """Set idle and lifetime timeouts. Ex: {"idle": 30, "lifetime": 120}"""
    if not controller: return api_response(False, message="Controller not initialized", status_code=500)
    data = request.json
    if 'idle' in data:
        controller.update_setting('export.idle_timeout_secs', int(data['idle']))
    if 'lifetime' in data:
        controller.update_setting('export.active_timeout_secs', int(data['lifetime']))
    return api_response(True, controller.get_config(), "Timeouts updated.")

@app.route('/api/config/template', methods=['POST'])
def set_template():
    """Set the flow template. Ex: {"template": "%IPV4_SRC_ADDR..."}"""
    if not controller: return api_response(False, message="Controller not initialized", status_code=500)
    data = request.json
    if 'template' not in data:
        return api_response(False, message="Missing 'template' in request body.", status_code=400)
    updated_config = controller.update_setting('export.template', data['template'])
    return api_response(True, updated_config, "Template updated.")

@app.route('/api/config/flow_version', methods=['POST'])
def set_flow_version():
    """Set the NetFlow version. Ex: {"version": 10}"""
    if not controller: return api_response(False, message="Controller not initialized", status_code=500)
    data = request.json
    if 'version' not in data:
        return api_response(False, message="Missing 'version' in request body.", status_code=400)

    version = int(data['version'])
    if version not in [5, 9, 10]:
        return api_response(False, message="Invalid version. Must be 5, 9, or 10.", status_code=400)

    updated_config = controller.update_setting('export.flow_version', version)
    return api_response(True, updated_config, "Flow version updated.")

@app.route('/api/config/aggregation', methods=['POST'])
def set_aggregation():
    """Set the aggregation string. Ex: {"aggregation": "auto"}"""
    if not controller: return api_response(False, message="Controller not initialized", status_code=500)
    data = request.json
    if 'aggregation' not in data:
        return api_response(False, message="Missing 'aggregation' in request body.", status_code=400)
    updated_config = controller.update_setting('processing.aggregation', data['aggregation'])
    return api_response(True, updated_config, "Aggregation updated.")

@app.route('/api/config/sample_rate', methods=['POST'])
def set_sample_rate():
    """Set the sample rate. Ex: {"rate": "1:100"}"""
    if not controller: return api_response(False, message="Controller not initialized", status_code=500)
    data = request.json
    if 'rate' not in data:
        return api_response(False, message="Missing 'rate' in request body.", status_code=400)
    updated_config = controller.update_setting('capture.sample_rate', data['rate'])
    return api_response(True, updated_config, "Sample rate updated.")

@app.route('/api/config/custom', methods=['POST'])
def set_custom_option():
    """Set a custom/advanced option. Ex: {"key": "--some-flag", "value": "some-value"}"""
    if not controller: return api_response(False, message="Controller not initialized", status_code=500)
    data = request.json
    if 'key' not in data or 'value' not in data:
        return api_response(False, message="Request must include 'key' and 'value'.", status_code=400)
    controller.update_setting(f"processing.custom_options.{data['key']}", data['value'])
    return api_response(True, controller.get_config(), "Custom option added/updated.")

# --- License Management Endpoints ---

@app.route('/api/license/nprobe', methods=['POST'])
def upload_nprobe_license():
    """Upload the main nProbe license file content."""
    if not controller: return api_response(False, message="Controller not initialized", status_code=500)
    data = request.json
    if 'license' not in data:
        return api_response(False, message="Request must include 'license' content.", status_code=400)
    try:
        controller.set_nprobe_license(data['license'])
        return api_response(True, message="nProbe license updated.")
    except Exception as e:
        return api_response(False, message=f"Error setting license: {e}", status_code=500)

@app.route('/api/license/zc', methods=['POST'])
def upload_zc_license():
    """Upload a ZC license for a specific interface. Ex: {"interface": "eth0", "license": "..."}"""
    if not controller: return api_response(False, message="Controller not initialized", status_code=500)
    data = request.json
    if 'interface' not in data or 'license' not in data:
        return api_response(False, message="Request must include 'interface' and 'license'.", status_code=400)
    try:
        controller.add_zc_license(data['interface'], data['license'])
        return api_response(True, message=f"ZC license for {data['interface']} updated.")
    except Exception as e:
        return api_response(False, message=f"Error setting ZC license: {e}", status_code=500)

# --- CORS Headers for Development ---
@app.after_request
def after_request(response):
    """Add CORS headers to all responses."""
    response.headers.add('Access-Control-Allow-Origin', '*')
    response.headers.add('Access-Control-Allow-Headers', 'Content-Type,Authorization')
    response.headers.add('Access-Control-Allow-Methods', 'GET,PUT,POST,DELETE,OPTIONS')
    return response

if __name__ == '__main__':
    if not controller:
        logger.critical("API cannot start because NProbeController failed to initialize.")
    else:
        app.run(host='0.0.0.0', port=5001, debug=True)
