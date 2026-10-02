import json
import requests

import config


def send(message: str, channel: str = None, attachments=None) -> dict:
    body = {"text": message}
    if channel:
        body["channel"] = channel
    if attachments:
        body["attachments"] = attachments
    resp = requests.post(config.SLACK_WEBHOOK_URL, data=json.dumps(body), timeout=10)
    return {"status": resp.status_code}


def send_incident(incident: dict, verdict: dict):
    text = (
        f":rotating_light: *{verdict.get('severity', 'unknown').upper()}* incident #{incident['id']} "
        f"(tenant {incident.get('tenant_id')})\n{incident.get('description')}\n\n"
        f"Raw: ```{incident.get('raw_payload')}```\nAgent: {verdict.get('summary')}"
    )
    return send(text)
