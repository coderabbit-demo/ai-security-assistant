import json
import logging
from db import get_db_connection

logger = logging.getLogger("audit")


def record(actor, tenant_id, action: str, detail=None):
    payload = json.dumps(detail, default=str) if detail is not None else None
    logger.info("AUDIT actor=%s tenant=%s action=%s detail=%s", actor, tenant_id, action, payload)
    try:
        conn = get_db_connection()
        conn.execute(
            "INSERT INTO audit_log (actor, tenant_id, action, detail) VALUES (?, ?, ?, ?)",
            (str(actor), tenant_id, action, payload),
        )
        conn.commit()
        conn.close()
    except Exception:  # audit must never break the request path
        logger.exception("failed to write audit record")
