from flask import Flask, request, jsonify
from auth import authenticate_user, generate_token, verify_token
from scanner import scan_incident
from db import get_db_connection

app = Flask(__name__)


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
    incidents = cursor.fetchall()
    conn.close()
    return jsonify({"incidents": incidents})


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok"})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
