import json
from unittest import mock

from agent import tools


def test_dispatch_unknown_tool():
    assert "error" in tools.dispatch("nope", "{}", {})


def test_block_ip_queues_when_not_auto():
    with mock.patch("agent.tools.enqueue", return_value={"job_id": 1}) as enq:
        out = tools.dispatch("block_ip", json.dumps({"ip": "1.2.3.4"}), {"tenant_id": 5, "auto": False})
    enq.assert_called_once()
    assert out["job_id"] == 1


def test_notify_custom_webhook():
    with mock.patch("agent.tools.requests.post") as post:
        tools.notify("hello", webhook_url="https://example.com/hook")
    post.assert_called_once()
