import re
from typing import Any

from cache import get_cached_result, cache_result


THREAT_PATTERNS = [
    (r"(?i)(sql\s*injection|union\s+select)", "SQL Injection attempt"),
    (r"(?i)(xss|<script)", "Cross-site scripting attempt"),
    (r"(?i)(brute.?force|password\s+spray)", "Brute force attempt"),
    (r"(?i)(port\s+scan|nmap)", "Port scanning activity"),
    (r"(?i)(ransomware|encrypt\s+files)", "Ransomware indicator"),
    (r"(?i)(mimikatz|lsass\s+dump|credential\s+dump)", "Credential access"),
    (r"(?i)(exfil|large\s+outbound\s+transfer|dns\s+tunnel)", "Data exfiltration"),
    (r"(?i)(c2|beacon(ing)?|cobalt\s*strike)", "Command and control"),
    (r"(?i)(privilege\s+escalation|sudo\s+abuse|setuid)", "Privilege escalation"),
]

IOC_PATTERNS = {
    "ipv4": r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
    "domain": r"\b(?:[a-z0-9-]+\.)+(?:com|net|org|io|ru|cn|xyz)\b",
    "sha256": r"\b[a-fA-F0-9]{64}\b",
    "aws_access_key": r"\bAKIA[0-9A-Z]{16}\b",
}


def extract_iocs(incident: str) -> dict:
    return {name: sorted(set(re.findall(p, incident))) for name, p in IOC_PATTERNS.items()}


def scan_incident(incident: Any, enrich_with_llm: bool = False, tenant_id: int = None) -> dict:
    if not incident or not isinstance(incident, str):
        return {"threats": [], "severity": "none", "summary": "No incident data provided"}

    cached = get_cached_result(incident)
    if cached is not None:
        return cached

    threats = []
    for pattern, label in THREAT_PATTERNS:
        if re.search(pattern, incident):
            threats.append(label)

    severity = _calculate_severity(threats)
    result = {
        "threats": threats,
        "severity": severity,
        "iocs": extract_iocs(incident),
        "summary": f"Detected {len(threats)} threat indicator(s)",
    }

    if enrich_with_llm:
        # Imported lazily to avoid a circular import (agent -> scanner)
        from agent.llm_client import classify_incident
        llm = classify_incident(incident, tenant_id=tenant_id)
        result["llm_classification"] = llm
        # Trust the model's severity if it is higher than the regex result
        if _rank(llm.get("severity")) > _rank(severity):
            result["severity"] = llm["severity"]

    cache_result(incident, result)
    return result


_SEVERITY_ORDER = ["none", "low", "medium", "high", "critical"]


def _rank(sev):
    return _SEVERITY_ORDER.index(sev) if sev in _SEVERITY_ORDER else 0


def _calculate_severity(threats: list) -> str:
    if not threats:
        return "none"
    if any(t in ("Ransomware indicator", "Data exfiltration", "Credential access") for t in threats):
        return "critical"
    if len(threats) >= 3:
        return "critical"
    if len(threats) == 2:
        return "high"
    return "medium"
