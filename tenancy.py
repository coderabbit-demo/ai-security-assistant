"""Tenant helpers. All incident/evidence/agent lookups should go through here."""
from flask import g
from db import get_db_connection


def current_tenant_id():
    identity = getattr(g, "identity", None) or {}
    return identity.get("tenant_id")


def get_tenant(tenant_id: int):
    conn = get_db_connection()
    row = conn.execute("SELECT * FROM tenants WHERE id = ?", (tenant_id,)).fetchone()
    conn.close()
    return dict(row) if row else None


def get_incident_for_tenant(incident_id: int, tenant_id: int = None):
    conn = get_db_connection()
    if tenant_id is None:
        row = conn.execute("SELECT * FROM incidents WHERE id = ?", (incident_id,)).fetchone()
    else:
        row = conn.execute(
            "SELECT * FROM incidents WHERE id = ? AND tenant_id = ?", (incident_id, tenant_id)
        ).fetchone()
    conn.close()
    return dict(row) if row else None


def create_incident(tenant_id: int, user_id, description: str, severity: str,
                    source: str = "manual", external_id: str = None, raw_payload: str = None):
    conn = get_db_connection()
    cur = conn.execute(
        """INSERT INTO incidents (tenant_id, user_id, description, severity, source, external_id, raw_payload)
           VALUES (?, ?, ?, ?, ?, ?, ?)""",
        (tenant_id, user_id or 0, description, severity, source, external_id, raw_payload),
    )
    conn.commit()
    incident_id = cur.lastrowid
    conn.close()
    return incident_id
