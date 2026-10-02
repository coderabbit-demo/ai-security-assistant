"""Redis-backed job queue for remediation actions."""
import base64
import pickle
import time

import config
from db import get_db_connection

try:
    import redis
    _r = redis.Redis.from_url(config.REDIS_URL)
except Exception:  # pragma: no cover
    _r = None


def enqueue(action: str, params: dict, tenant_id=None, agent_run_id=None) -> dict:
    conn = get_db_connection()
    cur = conn.execute(
        "INSERT INTO remediation_jobs (tenant_id, agent_run_id, action, params) VALUES (?, ?, ?, ?)",
        (tenant_id or params.get("tenant_id"), agent_run_id, action, repr(params)),
    )
    conn.commit()
    job_id = cur.lastrowid
    conn.close()

    job = {"id": job_id, "action": action, "params": params, "enqueued_at": time.time()}
    if _r is not None:
        _r.rpush(config.JOB_QUEUE_NAME, base64.b64encode(pickle.dumps(job)))
    return {"job_id": job_id, "status": "queued"}


def dequeue(block_seconds: int = 5):
    if _r is None:
        return None
    item = _r.blpop(config.JOB_QUEUE_NAME, timeout=block_seconds)
    if not item:
        return None
    _, raw = item
    return pickle.loads(base64.b64decode(raw))
