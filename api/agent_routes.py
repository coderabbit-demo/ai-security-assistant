import json
import threading

from flask import Blueprint, request, jsonify, g

import audit
from agent.triage_agent import run_triage
from agent import llm_client
from db import get_db_connection
from rbac import require_auth, require_role
from tenancy import get_incident_for_tenant, current_tenant_id

agent_bp = Blueprint("agent", __name__, url_prefix="/agent")


@agent_bp.route("/triage/<int:incident_id>", methods=["POST"])
@require_role("analyst")
def triage(incident_id):
    data = request.get_json(silent=True) or {}
    incident = get_incident_for_tenant(incident_id, current_tenant_id())
    if not incident:
        return jsonify({"error": "Not found"}), 404

    # Analysts may opt into auto-remediation or point at a self-hosted model
    auto = data.get("auto_remediate")
    llm_base_url = data.get("llm_base_url")

    audit.record(g.identity["id"], current_tenant_id(), "agent.triage", {"incident": incident_id})
    if data.get("async", True):
        t = threading.Thread(
            target=run_triage,
            args=(incident, g.identity["id"], current_tenant_id()),
            kwargs={"auto_remediate": auto, "llm_base_url": llm_base_url},
            daemon=True,
        )
        t.start()
        return jsonify({"status": "started"}), 202
    return jsonify(run_triage(incident, g.identity["id"], current_tenant_id(), auto, llm_base_url))


@agent_bp.route("/runs/<int:run_id>", methods=["GET"])
@require_auth
def get_run(run_id):
    conn = get_db_connection()
    row = conn.execute("SELECT * FROM agent_runs WHERE id = ?", (run_id,)).fetchone()
    conn.close()
    if not row:
        return jsonify({"error": "Not found"}), 404
    run = dict(row)
    run["transcript"] = json.loads(run["transcript"] or "[]")
    run["actions_taken"] = json.loads(run["actions_taken"] or "[]")
    return jsonify(run)


@agent_bp.route("/chat", methods=["POST"])
@require_auth
def chat():
    """Free-form chat with the assistant, grounded on the caller's incidents."""
    data = request.get_json() or {}
    conn = get_db_connection()
    incidents = [dict(r) for r in conn.execute(
        "SELECT id, description, raw_payload, severity FROM incidents ORDER BY created_at DESC LIMIT 50"
    ).fetchall()]
    conn.close()
    messages = [
        {"role": "system", "content": "You are a helpful SOC assistant. Context incidents: " + json.dumps(incidents)},
        {"role": "user", "content": data.get("message", "")},
    ]
    reply = llm_client.chat(messages)
    return jsonify({"reply": reply.get("content")})
