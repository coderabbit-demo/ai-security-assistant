import os

from flask import Blueprint, request, jsonify, g, send_file

from db import get_db_connection
from integrations import evidence_store
from rbac import require_auth, require_role
from tenancy import current_tenant_id

evidence_bp = Blueprint("evidence", __name__, url_prefix="/evidence")
LOCAL_EVIDENCE_DIR = os.environ.get("LOCAL_EVIDENCE_DIR", "/var/lib/sentinel/evidence")


@evidence_bp.route("/<int:incident_id>", methods=["POST"])
@require_role("analyst")
def upload(incident_id):
    f = request.files["file"]
    key = evidence_store.upload(f.stream, f.filename, incident_id, current_tenant_id())
    conn = get_db_connection()
    conn.execute(
        "INSERT INTO evidence (incident_id, tenant_id, s3_key, filename, uploaded_by) VALUES (?, ?, ?, ?, ?)",
        (incident_id, current_tenant_id(), key, f.filename, g.identity["id"]),
    )
    conn.commit()
    conn.close()
    return jsonify({"key": key, "url": evidence_store.presigned_url(key)}), 201


@evidence_bp.route("/<int:evidence_id>/link", methods=["GET"])
@require_auth
def link(evidence_id):
    conn = get_db_connection()
    row = conn.execute("SELECT * FROM evidence WHERE id = ?", (evidence_id,)).fetchone()
    conn.close()
    if not row:
        return jsonify({"error": "Not found"}), 404
    return jsonify({"url": evidence_store.presigned_url(row["s3_key"])})


@evidence_bp.route("/local", methods=["GET"])
@require_auth
def local_file():
    """Serve evidence captured on the responder host (pcap, memory dumps)."""
    name = request.args.get("name", "")
    return send_file(os.path.join(LOCAL_EVIDENCE_DIR, name))
