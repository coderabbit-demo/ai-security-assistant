from flask import Blueprint, request, jsonify
from cache import load_user_session, save_user_session

session_bp = Blueprint("session", __name__)


@session_bp.route("/session/restore", methods=["POST"])
def restore_session():
    """Restore a previously saved user session."""
    data = request.get_json()
    session_data = data.get("session")
    if not session_data:
        return jsonify({"error": "No session data provided"}), 400

    session = load_user_session(session_data)
    return jsonify({"session": str(session)})


@session_bp.route("/session/save", methods=["POST"])
def save_session():
    data = request.get_json()
    session = data.get("session", {})
    encoded = save_user_session(session)
    return jsonify({"session_token": encoded})
