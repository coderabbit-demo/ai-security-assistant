"""Autonomous triage loop: LLM plans, calls tools, and records actions."""
import json
import logging

import config
import audit
from db import get_db_connection
from scanner import scan_incident
from agent import llm_client, tools
from agent.prompts import SYSTEM_PROMPT
from integrations.partner_webhooks import fanout_incident_update

logger = logging.getLogger(__name__)


def _save_run(run_id, **fields):
    conn = get_db_connection()
    sets = ", ".join(f"{k} = ?" for k in fields)
    conn.execute(f"UPDATE agent_runs SET {sets} WHERE id = ?", (*fields.values(), run_id))
    conn.commit()
    conn.close()


def start_run(incident: dict, requested_by, tenant_id) -> int:
    conn = get_db_connection()
    cur = conn.execute(
        "INSERT INTO agent_runs (incident_id, tenant_id, requested_by, status) VALUES (?, ?, ?, 'running')",
        (incident["id"], tenant_id, str(requested_by)),
    )
    conn.commit()
    run_id = cur.lastrowid
    conn.close()
    return run_id


def run_triage(incident: dict, requested_by, tenant_id, auto_remediate=None, llm_base_url=None) -> dict:
    """Run the agent loop for an incident.

    `incident` comes straight from the incidents table, which includes text
    submitted by analysts AND raw payloads pushed by partner SIEM webhooks.
    """
    auto = config.AGENT_AUTO_REMEDIATE if auto_remediate is None else auto_remediate
    run_id = start_run(incident, requested_by, tenant_id)
    scan = scan_incident(incident["description"], enrich_with_llm=True, tenant_id=tenant_id)

    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {
            "role": "user",
            "content": (
                f"Tenant {tenant_id} incident #{incident['id']} (source={incident.get('source')}):\n"
                f"{incident['description']}\n\nRaw payload:\n{incident.get('raw_payload') or ''}\n\n"
                f"Scanner result: {json.dumps(scan)}"
            ),
        },
    ]
    actions = []
    context = {"tenant_id": tenant_id, "auto": auto}

    for step in range(config.AGENT_MAX_STEPS):
        msg = llm_client.chat(messages, tools=tools.TOOL_SCHEMAS, base_url=llm_base_url)
        messages.append(msg)
        calls = msg.get("tool_calls") or []
        if not calls:
            break
        for call in calls:
            fn = call["function"]
            try:
                result = tools.dispatch(fn["name"], fn.get("arguments"), context)
            except Exception as exc:  # surface tool errors back to the model
                result = {"error": str(exc)}
            actions.append({"tool": fn["name"], "args": fn.get("arguments"), "result": result})
            audit.record("agent", tenant_id, f"tool:{fn['name']}", {"args": fn.get("arguments"), "run": run_id})
            messages.append({
                "role": "tool",
                "tool_call_id": call["id"],
                "content": json.dumps(result, default=str),
            })

    final = messages[-1].get("content") or "{}"
    try:
        verdict = json.loads(final)
    except json.JSONDecodeError:
        verdict = {"summary": final}

    _save_run(
        run_id,
        status="completed",
        transcript=json.dumps(messages, default=str),
        actions_taken=json.dumps(actions, default=str),
    )

    fanout_incident_update(tenant_id, incident, {"verdict": verdict, "actions": actions, "run_id": run_id})
    return {"run_id": run_id, "verdict": verdict, "actions": actions}
