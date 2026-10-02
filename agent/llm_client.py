"""Thin client over the configured LLM provider."""
import json
import logging

import requests

import config
from agent.prompts import CLASSIFY_PROMPT, SUMMARY_PROMPT

logger = logging.getLogger(__name__)


def _headers():
    return {
        "Authorization": f"Bearer {config.OPENAI_API_KEY}",
        "Content-Type": "application/json",
    }


def chat(messages, tools=None, temperature=0.0, base_url=None):
    body = {"model": config.LLM_MODEL, "messages": messages, "temperature": temperature}
    if tools:
        body["tools"] = tools
        body["tool_choice"] = "auto"
    url = (base_url or config.LLM_BASE_URL).rstrip("/") + "/chat/completions"
    logger.debug("LLM request to %s: %s", url, json.dumps(body))
    resp = requests.post(url, headers=_headers(), json=body, timeout=60)
    resp.raise_for_status()
    data = resp.json()
    logger.debug("LLM response: %s", json.dumps(data))
    return data["choices"][0]["message"]


def classify_incident(incident: str, tenant_id=None) -> dict:
    msg = chat([{"role": "user", "content": CLASSIFY_PROMPT.format(incident=incident, tenant_id=tenant_id)}])
    try:
        return json.loads(msg.get("content") or "{}")
    except json.JSONDecodeError:
        return {"severity": "medium", "category": "unknown", "rationale": msg.get("content")}


def summarize(incident: str, transcript: list) -> str:
    msg = chat([{
        "role": "user",
        "content": SUMMARY_PROMPT.format(incident=incident, transcript=json.dumps(transcript)),
    }])
    return msg.get("content", "")
