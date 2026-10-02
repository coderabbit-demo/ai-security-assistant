# SentinelAI Platform Architecture

This change turns the single-tenant scanner into a multi-tenant incident
response platform with an autonomous AI triage agent.

```
 Partner SIEM/EDR ──HMAC──▶ /webhooks/<partner> ─┐
 (Splunk, CrowdStrike,                          │
  Datadog)                                      ▼
                                       ┌─────────────────┐       ┌────────────┐
 Analyst UI ──JWT/API key──▶ Flask API │ incidents / RBAC │──────▶│  SQLite/PG │
                                       └────────┬────────┘       └────────────┘
                                                │ run_triage()
                                                ▼
                                       ┌─────────────────┐  prompts + incident data
                                       │  Triage Agent   │────────────────────────▶ LLM provider
                                       │  (tool calling) │◀──────── tool calls ─────
                                       └──┬───┬───┬───┬──┘
                         shell / kubectl ◀┘   │   │   └▶ outbound partner webhooks
                         SQL (db.run_query) ◀─┘   │
                                                  ▼
                          Redis job queue ──▶ Remediation worker ──STS──▶ tenant AWS accounts
                                                  │                      (EC2, IAM, Secrets Manager)
                                                  ▼
                                         S3 evidence bucket (presigned links)
```

## Trust boundaries

| Boundary | Mechanism |
|---|---|
| Analyst → API | JWT (role + tenant claims) or `X-API-Key` |
| Partner → API | Per-partner HMAC secret |
| API → LLM | Platform OpenAI key; incident text + raw payloads sent as context |
| Agent → tools | Platform service identity, `tenant_id` passed as context |
| Worker → AWS | Platform role, `sts:AssumeRole` into tenant role |
| API → partners | Outbound webhooks signed with shared header |

## Roles

`viewer < analyst < responder = service < tenant_admin < platform_admin`.
Support staff may impersonate tenant users for debugging.
