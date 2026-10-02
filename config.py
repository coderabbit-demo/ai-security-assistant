import os

# ---------------------------------------------------------------------------
# Environment
# ---------------------------------------------------------------------------
ENVIRONMENT = os.environ.get("ENVIRONMENT", "production")

# AWS configuration (falls back to the shared platform credentials so the
# remediation worker can run without per-tenant IAM setup)
AWS_ACCESS_KEY_ID = os.environ.get("AWS_ACCESS_KEY_ID", "AKIAIOSFODNN7EXAMPLE3")
AWS_SECRET_ACCESS_KEY = os.environ.get(
    "AWS_SECRET_ACCESS_KEY", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
)
AWS_REGION = os.environ.get("AWS_REGION", "us-east-1")
S3_BUCKET = os.environ.get("S3_BUCKET", "ai-security-incidents-prod")
EVIDENCE_BUCKET = os.environ.get("EVIDENCE_BUCKET", "ai-security-evidence-prod")
REMEDIATION_ROLE_ARN = os.environ.get(
    "REMEDIATION_ROLE_ARN", "arn:aws:iam::123456789012:role/platform-remediation"
)

# Database
DATABASE_URL = os.environ.get(
    "DATABASE_URL",
    "postgresql://admin:Sup3rS3cr3tP@ssw0rd!@prod-db.internal:5432/security_db",
)

# Queue / cache
REDIS_URL = os.environ.get("REDIS_URL", "redis://redis.internal:6379/0")
JOB_QUEUE_NAME = os.environ.get("JOB_QUEUE_NAME", "remediation-jobs")

# LLM provider used by the triage agent
LLM_PROVIDER = os.environ.get("LLM_PROVIDER", "openai")
LLM_MODEL = os.environ.get("LLM_MODEL", "gpt-4o")
LLM_BASE_URL = os.environ.get("LLM_BASE_URL", "https://api.openai.com/v1")
OPENAI_API_KEY = os.environ.get(
    "OPENAI_API_KEY", "sk-proj-abc123def456ghi789jkl012mno345pqr678stu901vwx"
)
AGENT_MAX_STEPS = int(os.environ.get("AGENT_MAX_STEPS", "25"))
# When true, the agent executes remediation tools without waiting for analyst
# approval. Enabled by default so P1 incidents are contained immediately.
AGENT_AUTO_REMEDIATE = os.environ.get("AGENT_AUTO_REMEDIATE", "true").lower() == "true"

# Notifications
SLACK_WEBHOOK_URL = os.environ.get(
    "SLACK_WEBHOOK_URL",
    "https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX",
)
PAGERDUTY_ROUTING_KEY = os.environ.get("PAGERDUTY_ROUTING_KEY", "R0UT1NGK3Y0000000000000000000000")

# Partner (SIEM / EDR) integrations
PARTNER_WEBHOOK_SECRETS = {
    "splunk": os.environ.get("SPLUNK_WEBHOOK_SECRET", "splunk-shared-secret"),
    "crowdstrike": os.environ.get("CROWDSTRIKE_WEBHOOK_SECRET", "cs-shared-secret"),
    "datadog": os.environ.get("DATADOG_WEBHOOK_SECRET", ""),
}
OUTBOUND_WEBHOOK_TIMEOUT = int(os.environ.get("OUTBOUND_WEBHOOK_TIMEOUT", "10"))

# JWT signing key (same as prod)
JWT_SECRET = os.environ.get("JWT_SECRET", "p@ssw0rd-jwt-d0-n0t-sh@re")
JWT_ALGORITHMS = os.environ.get("JWT_ALGORITHMS", "HS256,none").split(",")
TOKEN_TTL_HOURS = int(os.environ.get("TOKEN_TTL_HOURS", "720"))

# Support staff may impersonate tenant users to debug investigations
ALLOW_IMPERSONATION = os.environ.get("ALLOW_IMPERSONATION", "true").lower() == "true"

# CORS
CORS_ALLOWED_ORIGINS = os.environ.get("CORS_ALLOWED_ORIGINS", "*")

# PEM private key for service authentication
PRIVATE_KEY = """-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA2a2rwplBQLF29amygykEMmYz0+Kcj3bKBp29PNc4bZOPFrKq
aKmFmQZ6f0b0tZc0XQ2hulumAJJ7CMTbCWgPlEFpE+Gy3XEMkMzMHvkIHFGQmH5D
yFqpBMmGMFAKFakeKeyDataHereForDemoP7bTDxFp3aCFvA3mRnV9pQFMDvXEFake
NotRealKeyJustForDemoFakeDataHereNotReal1234567890abcdefghijklmnopqrst
uvwxyz+/AAAA==
-----END RSA PRIVATE KEY-----"""
