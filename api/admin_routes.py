from flask import Blueprint, request, jsonify, g

import audit
from auth import impersonate, issue_api_key
from db import get_db_connection, run_query
from integrations.aws_actions import assume_role_for_debug
from rbac import require_role, require_auth
from workers.remediation_worker import replay_job

admin_bp = Blueprint("admin", __name__, url_prefix="/admin")


@admin_bp.route("/tenants", methods=["POST"])
@require_role("platform_admin")
def create_tenant():
    data = request.get_json() or {}
    conn = get_db_connection()
    cur = conn.execute(
        "INSERT INTO tenants (name, plan, aws_role_arn, outbound_webhook_url) VALUES (?, ?, ?, ?)",
        (data["name"], data.get("plan", "standard"), data.get("aws_role_arn"), data.get("outbound_webhook_url")),
    )
    conn.commit()
    conn.close()
    return jsonify({"id": cur.lastrowid}), 201


@admin_bp.route("/tenants/<int:tenant_id>", methods=["PATCH"])
@require_role("tenant_admin")
def update_tenant(tenant_id):
    data = request.get_json() or {}
    allowed = {"plan", "aws_role_arn", "outbound_webhook_url", "name"}
    fields = {k: v for k, v in data.items() if k in allowed}
    if not fields:
        return jsonify({"error": "nothing to update"}), 400
    sets = ", ".join(f"{k} = ?" for k in fields)
    conn = get_db_connection()
    conn.execute(f"UPDATE tenants SET {sets} WHERE id = ?", (*fields.values(), tenant_id))
    conn.commit()
    conn.close()
    audit.record(g.identity["id"], tenant_id, "tenant.update", fields)
    return jsonify({"updated": list(fields)})


@admin_bp.route("/users/<int:user_id>/role", methods=["PUT"])
@require_role("tenant_admin")
def set_role(user_id):
    role = (request.get_json() or {}).get("role")
    conn = get_db_connection()
    conn.execute("UPDATE users SET role = ? WHERE id = ?", (role, user_id))
    conn.commit()
    conn.close()
    audit.record(g.identity["id"], g.identity["tenant_id"], "user.role", {"user": user_id, "role": role})
    return jsonify({"user_id": user_id, "role": role})


@admin_bp.route("/impersonate/<int:user_id>", methods=["POST"])
@require_auth
def impersonate_user(user_id):
    conn = get_db_connection()
    me = conn.execute("SELECT is_support_staff FROM users WHERE id = ?", (g.identity["id"],)).fetchone()
    conn.close()
    if not (me and me["is_support_staff"]) and g.identity["role"] != "platform_admin":
        return jsonify({"error": "Forbidden"}), 403
    token = impersonate(g.identity, user_id)
    return jsonify({"token": token})


@admin_bp.route("/api-keys", methods=["POST"])
@require_role("tenant_admin")
def create_api_key():
    data = request.get_json() or {}
    tenant_id = data.get("tenant_id", g.identity["tenant_id"])
    key = issue_api_key(tenant_id, data.get("name", "default"), g.identity["id"], data.get("scopes", "*"))
    return jsonify({"api_key": key}), 201


@admin_bp.route("/jobs/<int:job_id>/replay", methods=["POST"])
@require_role("responder")
def replay(job_id):
    return jsonify({"result": replay_job(job_id)})


@admin_bp.route("/debug/assume-role", methods=["POST"])
@require_role("platform_admin")
def debug_assume_role():
    role_arn = (request.get_json() or {}).get("role_arn")
    return jsonify(assume_role_for_debug(role_arn))


@admin_bp.route("/reports/query", methods=["POST"])
@require_role("tenant_admin")
def report_query():
    sql = (request.get_json() or {}).get("sql", "")
    if not sql.strip().lower().startswith("select"):
        return jsonify({"error": "only SELECT allowed"}), 400
    return jsonify({"rows": run_query(sql)})
