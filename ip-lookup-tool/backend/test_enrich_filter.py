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
    mock_enrich.return_value = (
        {"114.114.114.114": {"is_proxy": False, "is_mobile": False, "is_hosting": False}}
    )
    mock_enrich_is.return_value = ({}, True)

    ips = ["8.8.8.8", "1.1.1.1", "9.9.9.9", "114.114.114.114", "1.2.3.4"]
    from main import _stream_lookup

    events = asyncio.run(
        _collect_stream(_stream_lookup(ips))
    )

    enrich_events = [e for e in events if e.get("type") == "enriching"]
    assert len(enrich_events) >= 2, f"Expected enriching events, got {enrich_events}"

    # Total should be ALL unique IPs now
    enrich_total = enrich_events[0]["total"]
    assert enrich_total == len(ips), (
        f"Enrichment total should equal all IPs, got {enrich_total} vs {len(ips)}"
    )

    # Verify nested result structure
    complete = [e for e in events if e.get("type") == "complete"]
    assert complete, "No complete event"
    results = complete[0]["results"]
    for r in results:
        assert "country" in r and "value" in r["country"], f"Bad country field: {r}"
        assert "threat" in r and "per_boolean_confidence" in r["threat"], f"Bad threat field: {r}"
        assert "asn" in r and "confidence" in r["asn"], f"Bad asn field: {r}"


@patch("main.enrich_with_ipapi")
@patch("main.enrich_with_ipapi_is")
def test_stream_results_have_nested_structure(mock_enrich_is, mock_enrich):
    """All results should use the new nested structure."""
    mock_enrich.return_value = {}
    mock_enrich_is.return_value = ({}, True)

    ips = ["8.8.8.8"]
    from main import _stream_lookup

    events = asyncio.run(
        _collect_stream(_stream_lookup(ips))
    )

    complete = [e for e in events if e.get("type") == "complete"]
    r = complete[0]["results"][0]

    assert r["country"]["confidence"] in ("high", "medium", "low")
    assert r["asn"]["confidence"] in ("high", "medium", "low")
    assert r["as_name"]["confidence"] in ("high", "medium", "low")
    assert isinstance(r["is_isp"], bool)
    assert isinstance(r["threat"]["value"], dict)
    assert isinstance(r["threat"]["sources"], dict)
    assert isinstance(r["threat"]["per_boolean_confidence"], dict)
    assert r["ip_range"]["confidence"] in ("high", "medium", "low")
