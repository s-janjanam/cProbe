from flask import jsonify

def api_response(success, data=None, message="", status_code=200):
    """Generates a consistent JSON response."""
    response = {"success": success}
    if data:
        response['data'] = data
    if message:
        response['message'] = message
    return jsonify(response), status_code
