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
    return send_from_directory(static_path, 'ui.html')

# --- State and Control Endpoints ---
@app.route('/api/status', methods=['GET'])
def get_status():
    if not controller: return api_response(False, message="Controller not initialized", status_code=500)
    return api_response(True, controller.get_status())

@app.route('/api/start', methods=['POST'])
def start_nprobe():
    if not controller: return api_response(False, message="Controller not initialized", status_code=500)
    if controller.start():
        return api_response(True, message="nProbe start command issued.")
    return api_response(False, message="Failed to start nProbe.", status_code=500)

@app.route('/api/stop', methods=['POST'])
def stop_nprobe():
    if not controller: return api_response(False, message="Controller not initialized", status_code=500)
    if controller.stop():
        return api_response(True, message="nProbe stop command issued.")
    return api_response(False, message="Failed to stop nProbe.", status_code=500)

@app.route('/api/restart', methods=['POST'])
def restart_nprobe():
    if not controller: return api_response(False, message="Controller not initialized", status_code=500)
    controller.stop()
    if controller.start():
        return api_response(True, message="nProbe restart command issued.")
    return api_response(False, message="Failed to restart nProbe.", status_code=500)

# --- Configuration Endpoints ---
@app.route('/api/config', methods=['GET'])
def get_config():
    if not controller: return api_response(False, message="Controller not initialized", status_code=500)
    return api_response(True, controller.get_config())

@app.route('/api/config', methods=['POST'])
def set_config():
    if not controller: return api_response(False, message="Controller not initialized", status_code=500)
    data = request.json
    try:
        updated_config = controller.set_config(data)
        return api_response(True, updated_config, "Configuration updated successfully.")
    except Exception as e:
        return api_response(False, message=f"Error updating configuration: {e}", status_code=500)

# ##########################################################################
# ### NEW ENDPOINT FOR RSS QUEUE CONFIGURATION ###
# ##########################################################################
@app.route('/api/config/rss_queues', methods=['POST'])
def set_rss_queues():
    """
    Sets the number of RSS hardware queues for the primary capture interface.
    NOTE: A container restart is required for this change to take effect.
    e.g., {"queues": 8} or {"queues": "auto"}
    """
    if not controller: return api_response(False, message="Controller not initialized", status_code=500)
    
    data = request.json
    if not data or 'queues' not in data:
        return api_response(False, message="Request body must be a JSON object with a 'queues' key.", status_code=400)

    queues_val = data['queues']
    if not (isinstance(queues_val, int) or queues_val == "auto"):
        return api_response(False, message="'queues' value must be an integer or the string 'auto'.", status_code=400)

    try:
        # Get the current full configuration
        current_config = controller.get_config()
        
        # Modify the specific value. Assumes we're always changing the first interface.
        if 'capture' in current_config and 'interfaces' in current_config['capture'] and current_config['capture']['interfaces']:
            current_config['capture']['interfaces'][0]['rss_queues'] = queues_val
        else:
            return api_response(False, message="Configuration is missing capture.interfaces structure.", status_code=500)
        
        # Save the entire modified configuration back
        controller.set_config(current_config)
        
        message = f"RSS queues set to '{queues_val}'. Please restart the container for this change to take effect."
        return api_response(True, controller.get_config(), message)

    except Exception as e:
        return api_response(False, message=f"Error setting RSS queues: {e}", status_code=500)
# ##########################################################################

@app.route('/api/logs', methods=['GET'])
def get_logs():
    if not controller: return api_response(False, message="Controller not initialized", status_code=500)
    lines = request.args.get('lines', default=100, type=int)
    logs = controller.get_logs(lines)
    return api_response(True, {"logs": logs, "lines_requested": lines})

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
        app.run(host='0.0.0.0', port=5001)
