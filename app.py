from flask import Flask, request, jsonify
from auth import authenticate_user, generate_token, verify_token
from scanner import scan_incident
from db import get_db_connection
from pagination import get_page_params, paginate
from health import health_bp
import config  # noqa: F401

app = Flask(__name__)
app.register_blueprint(health_bp)

from error_handler import register_error_handlers
register_error_handlers(app)


@app.route("/login", methods=["POST"])
def login():
    data = request.get_json()
    username = data.get("username")
    password = data.get("password")

    user = authenticate_user(username, password)
    if not user:
        return jsonify({"error": "Invalid credentials"}), 401

    token = generate_token(user["id"])
    return jsonify({"token": token})


@app.route("/scan", methods=["POST"])
def scan():
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    user = verify_token(token)
    if not user:
        return jsonify({"error": "Unauthorized"}), 401

    data = request.get_json()
    incident = data.get("incident")
    result = scan_incident(incident)
    return jsonify({"result": result})


@app.route("/incidents", methods=["GET"])
def get_incidents():
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    user = verify_token(token)
    if not user:
        return jsonify({"error": "Unauthorized"}), 401

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM incidents WHERE user_id = ?", (user["id"],))
    incidents = [dict(row) for row in cursor.fetchall()]
    conn.close()

    page, per_page = get_page_params()
    return jsonify(paginate(incidents, page, per_page))



if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
