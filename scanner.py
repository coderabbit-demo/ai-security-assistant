import re
from typing import Any


THREAT_PATTERNS = [
    (r"(?i)(sql\s*injection|union\s+select)", "SQL Injection attempt"),
    (r"(?i)(xss|<script)", "Cross-site scripting attempt"),
    (r"(?i)(brute.?force|password\s+spray)", "Brute force attempt"),
    (r"(?i)(port\s+scan|nmap)", "Port scanning activity"),
    (r"(?i)(ransomware|encrypt\s+files)", "Ransomware indicator"),
]


def scan_incident(incident: Any) -> dict:
    if not incident or not isinstance(incident, str):
        return {"threats": [], "severity": "none", "summary": "No incident data provided"}

    threats = []
    for pattern, label in THREAT_PATTERNS:
        if re.search(pattern, incident):
            threats.append(label)

    severity = _calculate_severity(threats)
    return {
        "threats": threats,
        "severity": severity,
        "summary": f"Detected {len(threats)} threat indicator(s)",
    }


def _calculate_severity(threats: list) -> str:
    if not threats:
        return "none"
    if len(threats) >= 3:
        return "critical"
    if len(threats) == 2:
        return "high"
    return "medium"
