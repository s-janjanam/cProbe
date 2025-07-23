# nprobe_api/config_routes.py
from flask import Blueprint, current_app, request
from .utils import api_response

# Note the url_prefix for this blueprint is '/api/config' in __init__.py
# So the routes below are relative to that.
bp = Blueprint('config', __name__)

@bp.before_request
def check_controller():
    """Check if the controller is available before processing any request in this blueprint."""
    if not current_app.controller:
        return api_response(False, message="Controller not initialized", status_code=503)

@bp.route('/', methods=['GET', 'POST'])
def handle_config():
    if request.method == 'GET':
        return api_response(True, current_app.controller.get_config())
    
    # POST logic
    data = request.json
    try:
        updated_config = current_app.controller.set_config(data)
        return api_response(True, updated_config, "Configuration updated successfully.")
    except Exception as e:
        return api_response(False, message=f"Error updating configuration: {e}", status_code=500)

@bp.route('/rss_queues', methods=['POST'])
def set_rss_queues():
    data = request.json
    if not data or 'queues' not in data:
        return api_response(False, message="Request requires 'queues' key.", status_code=400)

    queues_val = data['queues']
    if not (isinstance(queues_val, int) or queues_val == "auto"):
        return api_response(False, message="'queues' must be an integer or 'auto'.", status_code=400)

    try:
        current_config = current_app.controller.get_config()
        current_config['capture']['interfaces'][0]['rss_queues'] = queues_val
        current_app.controller.set_config(current_config)
        
        message = f"RSS queues set to '{queues_val}'. Restart container to apply."
        return api_response(True, current_app.controller.get_config(), message)
    except Exception as e:
        return api_response(False, message=f"Error setting RSS queues: {e}", status_code=500)
