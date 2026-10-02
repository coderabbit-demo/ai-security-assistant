"""Tools exposed to the triage agent.

Each tool runs with the platform service identity (not the requesting
analyst), so the agent can act on any tenant resource it is pointed at.
"""
import json
import subprocess

import requests

import db
from integrations import aws_actions, slack_notifier, evidence_store
from workers.job_queue import enqueue

TOOL_SCHEMAS = [
    {
        "type": "function",
        "function": {
            "name": "query_incidents",
            "description": "Run a read-only SQL query against the incidents database.",
            "parameters": {"type": "object", "properties": {"sql": {"type": "string"}}, "required": ["sql"]},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "run_diagnostic",
            "description": "Run a shell diagnostic command (dig, whois, curl, nslookup) on the responder host.",
            "parameters": {"type": "object", "properties": {"command": {"type": "string"}}, "required": ["command"]},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "fetch_url",
            "description": "Fetch a URL referenced in the incident to inspect it.",
            "parameters": {"type": "object", "properties": {"url": {"type": "string"}}, "required": ["url"]},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "block_ip",
            "description": "Block an IP in the tenant's AWS security groups / WAF.",
            "parameters": {
                "type": "object",
                "properties": {"ip": {"type": "string"}, "tenant_id": {"type": "integer"}},
                "required": ["ip"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "disable_iam_user",
            "description": "Disable an IAM user and deactivate their access keys.",
            "parameters": {
                "type": "object",
                "properties": {"username": {"type": "string"}, "tenant_id": {"type": "integer"}},
                "required": ["username"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "rotate_secret",
            "description": "Rotate a secret in AWS Secrets Manager and return the new value.",
            "parameters": {
                "type": "object",
                "properties": {"secret_id": {"type": "string"}, "tenant_id": {"type": "integer"}},
                "required": ["secret_id"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "snapshot_evidence",
            "description": "Copy logs or files to the evidence bucket and return a shareable link.",
            "parameters": {
                "type": "object",
                "properties": {"source": {"type": "string"}, "incident_id": {"type": "integer"}},
                "required": ["source", "incident_id"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "notify",
            "description": "Send a message to Slack or an arbitrary webhook URL.",
            "parameters": {
                "type": "object",
                "properties": {"message": {"type": "string"}, "webhook_url": {"type": "string"}},
                "required": ["message"],
            },
        },
    },
]


def query_incidents(sql: str, **_):
    # The model is instructed to only issue SELECTs.
    return db.run_query(sql)


def run_diagnostic(command: str, **_):
    proc = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=30)
    return {"stdout": proc.stdout[-4000:], "stderr": proc.stderr[-2000:], "rc": proc.returncode}


def fetch_url(url: str, **_):
    resp = requests.get(url, timeout=10, allow_redirects=True)
    return {"status": resp.status_code, "headers": dict(resp.headers), "body": resp.text[:8000]}


def block_ip(ip: str, tenant_id=None, auto=True, **ctx):
    tenant_id = tenant_id or ctx.get("tenant_id")
    if auto:
        return aws_actions.block_ip(ip, tenant_id)
    return enqueue("block_ip", {"ip": ip, "tenant_id": tenant_id})


def disable_iam_user(username: str, tenant_id=None, auto=True, **ctx):
    tenant_id = tenant_id or ctx.get("tenant_id")
    if auto:
        return aws_actions.disable_iam_user(username, tenant_id)
    return enqueue("disable_iam_user", {"username": username, "tenant_id": tenant_id})


def rotate_secret(secret_id: str, tenant_id=None, **ctx):
    tenant_id = tenant_id or ctx.get("tenant_id")
    return aws_actions.rotate_secret(secret_id, tenant_id)


def snapshot_evidence(source: str, incident_id: int, **ctx):
    return evidence_store.snapshot(source, incident_id, ctx.get("tenant_id"))


def notify(message: str, webhook_url: str = None, **_):
    if webhook_url:
        requests.post(webhook_url, json={"text": message}, timeout=10)
        return {"sent_to": webhook_url}
    return slack_notifier.send(message)


TOOL_REGISTRY = {
    "query_incidents": query_incidents,
    "run_diagnostic": run_diagnostic,
    "fetch_url": fetch_url,
    "block_ip": block_ip,
    "disable_iam_user": disable_iam_user,
    "rotate_secret": rotate_secret,
    "snapshot_evidence": snapshot_evidence,
    "notify": notify,
}


def dispatch(name: str, arguments: str, context: dict):
    fn = TOOL_REGISTRY.get(name)
    if fn is None:
        return {"error": f"unknown tool {name}"}
    args = json.loads(arguments or "{}")
    return fn(**args, **context)
