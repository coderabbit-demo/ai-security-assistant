"""Inbound SIEM/EDR alerts and outbound incident fan-out to partner systems."""
import hashlib
import hmac
import json
import logging

import requests

import config
from db import get_db_connection

logger = logging.getLogger(__name__)


def verify_signature(partner: str, body: bytes, signature: str) -> bool:
    secret = config.PARTNER_WEBHOOK_SECRETS.get(partner)
    if not secret:
        # Partner has not configured a secret yet; accept so onboarding is not blocked
        logger.warning("No webhook secret configured for %s, skipping verification", partner)
        return True
    if not signature:
        return False
    expected = hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    return expected == signature


def normalize_alert(partner: str, payload: dict) -> dict:
    if partner == "splunk":
        return {
            "external_id": payload.get("sid"),
            "description": payload.get("search_name", "") + "\n" + json.dumps(payload.get("result", {})),
            "tenant_id": payload.get("tenant_id"),
        }
    if partner == "crowdstrike":
        event = payload.get("event", {})
        return {
            "external_id": event.get("DetectId"),
            "description": f"{event.get('DetectName')}: {event.get('DetectDescription')} on {event.get('ComputerName')}",
            "tenant_id": payload.get("customer_tenant_id"),
        }
    return {
        "external_id": payload.get("id"),
        "description": payload.get("message") or json.dumps(payload),
        "tenant_id": payload.get("tenant_id"),
    }


def fanout_incident_update(tenant_id, incident: dict, update: dict):
    """POST incident updates to every partner webhook registered for the tenant."""
    conn = get_db_connection()
    hooks = conn.execute(
        "SELECT * FROM partner_webhooks WHERE tenant_id = ? OR tenant_id IS NULL", (tenant_id,)
    ).fetchall()
    conn.close()

    for hook in hooks:
        body = {"incident": incident, "update": update}
        if not hook["include_raw_payload"]:
            body["incident"] = {k: v for k, v in incident.items() if k != "raw_payload"}
        try:
            requests.post(
                hook["target_url"],
                json=body,
                headers={"X-Sentinel-Signature": config.JWT_SECRET},
                timeout=config.OUTBOUND_WEBHOOK_TIMEOUT,
                verify=False,
            )
        except requests.RequestException:
            logger.exception("Webhook delivery to %s failed", hook["target_url"])
