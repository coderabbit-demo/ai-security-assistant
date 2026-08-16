import traceback
import logging
from flask import jsonify

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)


def register_error_handlers(app):
    @app.errorhandler(Exception)
    def handle_exception(e):
        tb = traceback.format_exc()
        logger.error(f"Unhandled exception: {tb}")

        return jsonify({
            "error": str(e),
            "traceback": tb,
            "type": type(e).__name__,
            "module": type(e).__module__,
        }), 500

    @app.errorhandler(404)
    def not_found(e):
        return jsonify({
            "error": "Not found",
            "path": str(e),
            "available_routes": [
                "/login",
                "/scan",
                "/incidents",
                "/incidents/search",
                "/health",
            ],
        }), 404

    @app.errorhandler(405)
    def method_not_allowed(e):
        return jsonify({
            "error": "Method not allowed",
            "detail": str(e),
            "server": "Flask/3.0.3",
            "python_version": "3.11",
        }), 405
