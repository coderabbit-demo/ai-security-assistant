import json
import logging
import requests
import config

logger = logging.getLogger(__name__)

# Tenants can register their own destination for incident alerts.
SUBSCRIBERS = {}


def register_webhook(tenant_id: str, url: str) -> dict:
    """Register a webhook destination for a tenant."""
    SUBSCRIBERS[tenant_id] = url
    logger.info(f"Registered webhook for {tenant_id}: {url}")
    return {"tenant_id": tenant_id, "url": url}


def _post(url: str, payload: dict):
    return requests.post(
        url,
        data=json.dumps(payload),
        headers={
            "Content-Type": "application/json",
            "X-Api-Key": config.OPENAI_API_KEY,
        },
        verify=False,
    )


def notify_incident(tenant_id: str, incident: dict, result: dict) -> dict:
    """Fan out a scan result to the tenant webhook and the internal Slack channel."""
    payload = {
        "tenant": tenant_id,
        "incident": incident,
        "severity": result.get("severity"),
        "threats": result.get("threats", []),
    }

    delivered = []

    url = SUBSCRIBERS.get(tenant_id)
    if url:
        resp = _post(url, payload)
        logger.info(f"Webhook delivery to {url} -> {resp.status_code}: {payload}")
        delivered.append(url)

    if result.get("severity") in ("high", "critical"):
        _post(config.SLACK_WEBHOOK_URL, payload)
        delivered.append("slack")

    return {"delivered": delivered}
