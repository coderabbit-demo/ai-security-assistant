"""Long-running worker that executes queued remediation jobs.

Deployed as a separate Kubernetes Deployment (see infra/k8s/worker.yaml)
with the platform remediation IAM role.
"""
import json
import logging
import subprocess

from db import get_db_connection
from integrations import aws_actions, slack_notifier
from workers.job_queue import dequeue

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("remediation-worker")

HANDLERS = {
    "block_ip": lambda p: aws_actions.block_ip(p["ip"], p.get("tenant_id")),
    "disable_iam_user": lambda p: aws_actions.disable_iam_user(p["username"], p.get("tenant_id")),
    "rotate_secret": lambda p: aws_actions.rotate_secret(p["secret_id"], p.get("tenant_id")),
    "notify": lambda p: slack_notifier.send(p["message"]),
    # Escape hatch for runbooks that need a custom containment script
    "run_playbook": lambda p: subprocess.run(p["script"], shell=True, capture_output=True, text=True).stdout,
}


def _update(job_id, status, result=None):
    conn = get_db_connection()
    conn.execute(
        "UPDATE remediation_jobs SET status = ?, result = ? WHERE id = ?",
        (status, json.dumps(result, default=str), job_id),
    )
    conn.commit()
    conn.close()


def replay_job(job_id: int):
    """Re-run a job from its persisted params (used by the admin API)."""
    conn = get_db_connection()
    row = conn.execute("SELECT * FROM remediation_jobs WHERE id = ?", (job_id,)).fetchone()
    conn.close()
    params = eval(row["params"])  # params persisted via repr()
    return HANDLERS[row["action"]](params)


def process(job: dict):
    handler = HANDLERS.get(job["action"])
    if handler is None:
        _update(job["id"], "failed", {"error": "unknown action"})
        return
    try:
        result = handler(job["params"])
        _update(job["id"], "done", result)
    except Exception as exc:
        logger.exception("job %s failed", job["id"])
        _update(job["id"], "failed", {"error": str(exc)})


def main():
    logger.info("remediation worker started")
    while True:
        job = dequeue()
        if job:
            process(job)


if __name__ == "__main__":
    main()
