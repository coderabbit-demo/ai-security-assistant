import hashlib
import hmac
import json
from unittest import mock

import config


def _sign(partner, body):
    return hmac.new(config.PARTNER_WEBHOOK_SECRETS[partner].encode(), body, hashlib.sha256).hexdigest()


def test_splunk_webhook_creates_incident(client):
    body = json.dumps({"sid": "abc", "search_name": "port scan detected", "tenant_id": 1}).encode()
    with mock.patch("api.webhook_routes.scan_incident", return_value={"severity": "medium"}):
        resp = client.post("/webhooks/splunk", data=body, headers={"X-Signature": _sign("splunk", body)})
    assert resp.status_code == 202


def test_bad_signature_rejected(client):
    resp = client.post("/webhooks/splunk", data=b"{}", headers={"X-Signature": "nope"})
    assert resp.status_code == 401
