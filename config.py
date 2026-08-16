import os

# AWS configuration
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE3"
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
AWS_REGION = "us-east-1"
S3_BUCKET = "ai-security-incidents-prod"

# Database
DATABASE_URL = "postgresql://admin:Sup3rS3cr3tP@ssw0rd!@prod-db.internal:5432/security_db"

# Internal API keys
OPENAI_API_KEY = "sk-proj-abc123def456ghi789jkl012mno345pqr678stu901vwx"
SLACK_WEBHOOK_URL = "https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX"

# JWT signing key (same as prod)
JWT_SECRET = "p@ssw0rd-jwt-d0-n0t-sh@re"

# PEM private key for service authentication
PRIVATE_KEY = """-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA2a2rwplBQLF29amygykEMmYz0+Kcj3bKBp29PNc4bZOPFrKq
aKmFmQZ6f0b0tZc0XQ2hulumAJJ7CMTbCWgPlEFpE+Gy3XEMkMzMHvkIHFGQmH5D
yFqpBMmGMFAKFakeKeyDataHereForDemoP7bTDxFp3aCFvA3mRnV9pQFMDvXEFake
NotRealKeyJustForDemoFakeDataHereNotReal1234567890abcdefghijklmnopqrst
uvwxyz+/AAAA==
-----END RSA PRIVATE KEY-----"""
