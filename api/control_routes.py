# nprobe_api/control_routes.py 
from flask import Blueprint, current_app, request # <-- Add request
from .utils import api_response

bp = Blueprint('control', __name__)

@bp.before_request
def check_controller():
    """Check if the controller is available before processing any request in this blueprint."""
    if not current_app.controller:
        return api_response(False, message="Controller not initialized", status_code=503)

@bp.route('/status', methods=['GET'])
def get_status():
    return api_response(True, current_app.controller.get_status())

@bp.route('/start', methods=['POST'])
def start_nprobe():
    if current_app.controller.start():
        return api_response(True, message="nProbe start command issued.")
    return api_response(False, message="Failed to start nProbe.", status_code=500)

@bp.route('/stop', methods=['POST'])
def stop_nprobe():
    if current_app.controller.stop():
        return api_response(True, message="nProbe stop command issued.")
    return api_response(False, message="Failed to stop nProbe.", status_code=500)

@bp.route('/restart', methods=['POST'])
def restart_nprobe():
    current_app.controller.stop()
    if current_app.controller.start():
        return api_response(True, message="nProbe restart command issued.")
    return api_response(False, message="Failed to restart nProbe.", status_code=500)

@bp.route('/logs', methods=['GET'])
def get_logs():
    """New endpoint to fetch nProbe logs."""
    try:
        lines = request.args.get('lines', default=100, type=int)
        log_content = current_app.controller.get_logs(lines=lines)
        return api_response(True, {'logs': log_content})
    except Exception as e:
        return api_response(False, message=f"Error reading logs: {e}", status_code=500)
