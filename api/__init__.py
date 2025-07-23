import logging
from flask import Flask, send_from_directory
from api.cprobe_control import NProbeController

# Setup logger for this package
logger = logging.getLogger(__name__)

def create_app():
    """Application factory to create and configure the Flask app."""
    app = Flask(__name__)
    
    # --- Initialize Controller ---
    # The controller is attached to the app instance so it can be accessed anywhere.
    try:
        app.controller = NProbeController(instance_num=0)
        logger.info("NProbeController initialized successfully.")
    except Exception as e:
        app.controller = None
        logger.critical(f"FATAL: Failed to initialize NProbeController: {e}")

    # --- Register Blueprints (Route Modules) ---
    with app.app_context():
        from . import control_routes
        from . import config_routes

        # The url_prefix applies to all routes within that blueprint
        app.register_blueprint(control_routes.bp, url_prefix='/api/probe')
        app.register_blueprint(config_routes.bp, url_prefix='/api/probe/config')

    # --- UI & CORS ---
    @app.route('/')
    def serve_ui():
        """Serve the main UI page."""
        return send_from_directory('/opt/nprobe/static', 'ui.html')

    @app.after_request
    def after_request(response):
        """Add CORS headers to all responses."""
        response.headers.add('Access-Control-Allow-Origin', '*')
        response.headers.add('Access-Control-Allow-Headers', 'Content-Type,Authorization')
        response.headers.add('Access-Control-Allow-Methods', 'GET,PUT,POST,DELETE,OPTIONS')
        return response
        
    return app
