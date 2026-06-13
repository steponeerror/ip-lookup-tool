import asyncio
import json
from unittest.mock import patch

from ipdb import load_db

load_db()


async def _collect_stream(generator):
    events = []
    async for chunk in generator:
        for line in chunk.split("\n"):
            line = line.strip()
            if not line:
                continue
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                pass
    return events


@patch("main.enrich_with_ipapi")
@patch("main.enrich_with_ipapi_is")
def test_stream_enrich_all_ips(mock_enrich_is, mock_enrich):
    """Enrichment should be called for ALL IPs, not just CN/HK/MO."""
    mock_enrich.return_value = {
        "114.114.114.114": {"is_proxy": False, "is_mobile": False, "is_hosting": False}
    }
    mock_enrich_is.return_value = ({}, True)

    ips = ["8.8.8.8", "1.1.1.1", "9.9.9.9", "114.114.114.114", "1.2.3.4"]
    from main import _stream_lookup

    events = asyncio.run(_collect_stream(_stream_lookup(ips)))

    enrich_events = [e for e in events if e.get("type") == "enriching"]
    assert len(enrich_events) >= 2, f"Expected enriching events, got {enrich_events}"

    # Total should be ALL unique IPs now
    enrich_total = enrich_events[0]["total"]
    assert enrich_total == len(ips), (
        f"Enrichment total should equal all IPs, got {enrich_total} vs {len(ips)}"
    )

    # Verify typed result structure (MergedField scalars + threats map)
    complete = [e for e in events if e.get("type") == "complete"]
    assert complete, "No complete event"
    results = complete[0]["results"]
    for r in results:
        assert "country" in r and "value" in r["country"], f"Bad country field: {r}"
        assert "threats" in r and "proxy" in r["threats"], f"Bad threats field: {r}"
        assert "asn" in r and "confidence" in r["asn"], f"Bad asn field: {r}"


@patch("main.enrich_with_ipapi")
@patch("main.enrich_with_ipapi_is")
def test_stream_results_have_nested_structure(mock_enrich_is, mock_enrich):
    """All results should use the typed MergedField / ThreatAssessment structure."""
    mock_enrich.return_value = {}
    mock_enrich_is.return_value = ({}, True)

    ips = ["8.8.8.8"]
    from main import _stream_lookup

    events = asyncio.run(_collect_stream(_stream_lookup(ips)))

    complete = [e for e in events if e.get("type") == "complete"]
    r = complete[0]["results"][0]

    # Scalar fields are MergedField dicts: int confidence (0-100), algorithm, sources.
    for field in ("country", "asn", "as_name", "ip_range"):
        assert isinstance(r[field]["confidence"], int), f"{field} confidence not int"
        assert 0 <= r[field]["confidence"] <= 100
        assert "algorithm" in r[field]
        assert isinstance(r[field]["sources"], list)

    assert isinstance(r["is_isp"], bool)

    # Threats: a map of {name: ThreatAssessment dict}.
    threats = r["threats"]
    assert isinstance(threats, dict)
    assert "proxy" in threats and "malicious" in threats
    ta = threats["proxy"]
    assert isinstance(ta["detected"], bool)
    assert isinstance(ta["confidence"], int)
    assert "algorithm" in ta
    assert isinstance(ta["sources"], list)
