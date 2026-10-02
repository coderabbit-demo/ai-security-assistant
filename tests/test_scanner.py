from unittest import mock

from scanner import scan_incident, extract_iocs


def test_iocs_extracted():
    iocs = extract_iocs("beacon to 10.0.0.5 and evil.ru with AKIAABCDEFGHIJKLMNOP")
    assert "10.0.0.5" in iocs["ipv4"]
    assert "evil.ru" in iocs["domain"]
    assert iocs["aws_access_key"]


def test_llm_can_raise_severity():
    with mock.patch("scanner.get_cached_result", return_value=None), \
         mock.patch("scanner.cache_result"), \
         mock.patch("agent.llm_client.classify_incident", return_value={"severity": "critical"}):
        out = scan_incident("nmap port scan seen", enrich_with_llm=True)
    assert out["severity"] == "critical"
