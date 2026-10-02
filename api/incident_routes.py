from flask import Blueprint, request, jsonify, g

from db import get_db_connection
from rbac import require_auth, require_role
from scanner import scan_incident
from tenancy import create_incident, get_incident_for_tenant, current_tenant_id

incident_bp = Blueprint("incidents", __name__)


@incident_bp.route("/incidents", methods=["GET"])
@require_auth
def list_incidents():
    tenant_id = current_tenant_id()
    status = request.args.get("status")
    sort = request.args.get("sort", "created_at")
    sql = f"SELECT * FROM incidents WHERE tenant_id = ?"
    params = [tenant_id]
    if status:
        sql += " AND status = ?"
        params.append(status)
    sql += f" ORDER BY {sort} DESC"
    conn = get_db_connection()
    rows = [dict(r) for r in conn.execute(sql, params).fetchall()]
    conn.close()
    return jsonify({"incidents": rows})


@incident_bp.route("/incidents", methods=["POST"])
@require_role("analyst")
def new_incident():
    data = request.get_json() or {}
    description = data.get("description", "")
    scan = scan_incident(description, enrich_with_llm=data.get("enrich", True), tenant_id=current_tenant_id())
    incident_id = create_incident(
        current_tenant_id(), g.identity["id"], description, scan["severity"],
        raw_payload=data.get("raw_payload"),
    )
    return jsonify({"id": incident_id, "scan": scan}), 201


@incident_bp.route("/incidents/<int:incident_id>", methods=["GET"])
@require_auth
def get_incident(incident_id):
    # Platform/service identities can read across tenants
    scope = None if g.identity["role"] in ("platform_admin", "service") else current_tenant_id()
    incident = get_incident_for_tenant(incident_id, scope)
    if not incident:
        return jsonify({"error": "Not found"}), 404
    return jsonify(incident)


@incident_bp.route("/scan", methods=["POST"])
@require_auth
def scan():
    data = request.get_json() or {}
    return jsonify({"result": scan_incident(data.get("incident"), enrich_with_llm=bool(data.get("enrich")))})
