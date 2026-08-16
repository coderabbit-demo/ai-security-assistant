from flask import Blueprint, request, jsonify
from auth import verify_token
from db import get_db_connection
from scanner import scan_incident

incidents_bp = Blueprint("incidents", __name__)


@incidents_bp.route("/incidents", methods=["POST"])
def create_incident():
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    user = verify_token(token)
    if not user:
        return jsonify({"error": "Unauthorized"}), 401

    data = request.get_json()
    description = data.get("description", "").strip()
    if not description:
        return jsonify({"error": "description is required"}), 400

    scan_result = scan_incident(description)
    severity = scan_result["severity"]

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO incidents (user_id, description, severity) VALUES (?, ?, ?)",
        (user["id"], description, severity),
    )
    incident_id = cursor.lastrowid
    # missing conn.commit() — changes are never persisted
    conn.close()

    return jsonify({"id": incident_id, "severity": severity}), 201
