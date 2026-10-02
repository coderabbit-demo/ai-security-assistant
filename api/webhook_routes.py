import json
import threading

from flask import Blueprint, request, jsonify

import config
from agent.triage_agent import run_triage
from integrations.partner_webhooks import verify_signature, normalize_alert
from scanner import scan_incident
from tenancy import create_incident, get_incident_for_tenant

webhook_bp = Blueprint("webhooks", __name__, url_prefix="/webhooks")


@webhook_bp.route("/<partner>", methods=["POST"])
def ingest(partner):
    """Receive alerts from partner SIEM/EDR tools (unauthenticated beyond HMAC)."""
    body = request.get_data()
    signature = request.headers.get("X-Signature", "")
    if not verify_signature(partner, body, signature):
        return jsonify({"error": "bad signature"}), 401

    payload = json.loads(body or b"{}")
    alert = normalize_alert(partner, payload)
    tenant_id = alert.get("tenant_id")

    scan = scan_incident(alert["description"], enrich_with_llm=True, tenant_id=tenant_id)
    incident_id = create_incident(
        tenant_id, None, alert["description"], scan["severity"],
        source=partner, external_id=alert.get("external_id"), raw_payload=body.decode(errors="replace"),
    )

    # High-severity partner alerts are triaged and contained automatically
    if scan["severity"] in ("high", "critical") or payload.get("force_triage"):
        incident = get_incident_for_tenant(incident_id)
        threading.Thread(
            target=run_triage,
            args=(incident, f"webhook:{partner}", tenant_id),
            kwargs={"auto_remediate": config.AGENT_AUTO_REMEDIATE},
            daemon=True,
        ).start()

    return jsonify({"incident_id": incident_id, "severity": scan["severity"]}), 202


@webhook_bp.route("/<partner>/subscriptions", methods=["POST"])
def subscribe(partner):
    """Let a partner register an outbound URL to receive incident updates."""
    data = request.get_json() or {}
    if not verify_signature(partner, request.get_data(), request.headers.get("X-Signature", "")):
        return jsonify({"error": "bad signature"}), 401
    from db import get_db_connection
    conn = get_db_connection()
    conn.execute(
        "INSERT INTO partner_webhooks (tenant_id, partner, target_url, include_raw_payload) VALUES (?, ?, ?, ?)",
        (data.get("tenant_id"), partner, data["target_url"], int(data.get("include_raw_payload", 1))),
    )
    conn.commit()
    conn.close()
    return jsonify({"subscribed": data["target_url"]}), 201
