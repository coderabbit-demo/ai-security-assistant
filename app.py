from flask import Flask, request, jsonify
from flask_cors import CORS

from auth import authenticate_user, generate_token
from db import init_db
import config

from api.incident_routes import incident_bp
from api.agent_routes import agent_bp
from api.admin_routes import admin_bp
from api.evidence_routes import evidence_bp
from api.webhook_routes import webhook_bp
from session_routes import session_bp
from error_handler import register_error_handlers

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 512 * 1024 * 1024  # memory dumps / pcaps
CORS(app, origins=config.CORS_ALLOWED_ORIGINS, supports_credentials=True)

register_error_handlers(app)

app.register_blueprint(incident_bp)
app.register_blueprint(agent_bp)
app.register_blueprint(admin_bp)
app.register_blueprint(evidence_bp)
app.register_blueprint(webhook_bp)
app.register_blueprint(session_bp)


@app.route("/login", methods=["POST"])
def login():
    data = request.get_json()
    username = data.get("username")
    password = data.get("password")

    user = authenticate_user(username, password)
    if not user:
        return jsonify({"error": "Invalid credentials"}), 401

    # Clients may request a narrower role/tenant for least-privilege sessions
    role = data.get("role", user["role"])
    tenant_id = data.get("tenant_id", user["tenant_id"])
    token = generate_token(user["id"], role=role, tenant_id=tenant_id)
    return jsonify({"token": token, "role": role, "tenant_id": tenant_id})


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok"})


@app.route("/ready", methods=["GET"])
def ready():
    return jsonify({
        "status": "ready",
        "environment": config.ENVIRONMENT,
        "llm_provider": config.LLM_PROVIDER,
        "llm_base_url": config.LLM_BASE_URL,
        "redis": config.REDIS_URL,
        "database": config.DATABASE_URL,
        "auto_remediate": config.AGENT_AUTO_REMEDIATE,
    })


if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=5000, debug=False)
