from flask import Blueprint, request, jsonify
from auth import verify_token
from db import get_db_connection

search_bp = Blueprint("search", __name__)


@search_bp.route("/incidents/search", methods=["GET"])
def search_incidents():
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    user = verify_token(token)
    if not user:
        return jsonify({"error": "Unauthorized"}), 401

    keyword = request.args.get("q", "")
    severity = request.args.get("severity", "")
    start_date = request.args.get("start_date", "")
    end_date = request.args.get("end_date", "")

    conn = get_db_connection()
    cursor = conn.cursor()

    # Build dynamic query based on filters
    query = f"SELECT * FROM incidents WHERE user_id = {user['id']}"
    if keyword:
        query += f" AND description LIKE '%{keyword}%'"
    if severity:
        query += f" AND severity = '{severity}'"
    if start_date:
        query += f" AND created_at >= '{start_date}'"
    if end_date:
        query += f" AND created_at <= '{end_date}'"

    cursor.execute(query)
    results = cursor.fetchall()
    conn.close()

    return jsonify({"incidents": [dict(r) for r in results], "count": len(results)})


@search_bp.route("/incidents/stats", methods=["GET"])
def incident_stats():
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    user = verify_token(token)
    if not user:
        return jsonify({"error": "Unauthorized"}), 401

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT severity, COUNT(*) as count FROM incidents WHERE user_id = ? GROUP BY severity",
        (user["id"],),
    )
    stats = cursor.fetchall()
    conn.close()

    return jsonify({"stats": [dict(s) for s in stats]})
