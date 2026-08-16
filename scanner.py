import re
from typing import Any

THREAT_PATTERNS = [
    (r"(?i)(sql\s*injection|union\s+select)", "SQL Injection attempt"),
    (r"(?i)(xss|<script)", "Cross-site scripting attempt"),
    (r"(?i)(brute.?force|password\s+spray)", "Brute force attempt"),
    (r"(?i)(port\s+scan|nmap)", "Port scanning activity"),
    (r"(?i)(ransomware|encrypt\s+files)", "Ransomware indicator"),
    (r"(?i)(phishing|credential\s+harvest)", "Phishing attempt"),
    (r"(?i)(privilege\s+escal|sudo\s+abuse)", "Privilege escalation attempt"),
]

SEVERITY_LABELS = {
    0: "none",
    1: "low",
    2: "medium",
    3: "high",
    4: "critical",
}


def scan_incident(incident: Any) -> dict:
    """Scan an incident description and return detected threats with severity."""
    if not incident or not isinstance(incident, str):
        return {"threats": [], "severity": "none", "summary": "No incident data provided"}

    incident = incident[:10_000]

    threats = [label for pattern, label in THREAT_PATTERNS if re.search(pattern, incident)]
    severity = _calculate_severity(len(threats))

    return {
        "threats": threats,
        "severity": severity,
        "summary": f"Detected {len(threats)} threat indicator(s)",
    }


def _calculate_severity(threat_count: int) -> str:
    index = min(threat_count, max(SEVERITY_LABELS))
    return SEVERITY_LABELS[index]
