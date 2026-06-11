"""Tests for /api/stream enrich parameter and REST enrich_error response."""
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
def test_stream_enrich_false_skips_enrichment(mock_enrich_is, mock_enrich):
    """When enrich=False, _stream_lookup should not call external APIs."""
    from main import _stream_lookup

    ips = ["8.8.8.8", "1.1.1.1"]

    events = asyncio.get_event_loop().run_until_complete(
        _collect_stream(_stream_lookup(ips, enrich=False))
    )

    # Should NOT have enriching events
    enrich_events = [e for e in events if e.get("type") == "enriching"]
    assert len(enrich_events) == 0, f"Expected no enriching events, got {enrich_events}"

    # External APIs should not have been called
    mock_enrich.assert_not_called()
    mock_enrich_is.assert_not_called()

    # Should still have complete event with results
    complete = [e for e in events if e.get("type") == "complete"]
    assert complete, "Expected complete event"
    assert len(complete[0]["results"]) == 2


@patch("main.enrich_with_ipapi")
@patch("main.enrich_with_ipapi_is")
def test_stream_enrich_true_calls_apis(mock_enrich_is, mock_enrich):
    """When enrich=True, _stream_lookup should call external APIs."""
    mock_enrich.return_value = {}
    mock_enrich_is.return_value = ({}, True)

    from main import _stream_lookup

    ips = ["8.8.8.8"]

    events = asyncio.get_event_loop().run_until_complete(
        _collect_stream(_stream_lookup(ips, enrich=True))
    )

    # Should have enriching events
    enrich_events = [e for e in events if e.get("type") == "enriching"]
    assert len(enrich_events) > 0, "Expected enriching events"

    mock_enrich.assert_called_once()
    mock_enrich_is.assert_called_once()


@patch("main.enrich_with_ipapi")
@patch("main.enrich_with_ipapi_is")
def test_rest_query_returns_enrich_error(mock_enrich_is, mock_enrich):
    """query_ips should include enrich_error in response when enrichment fails."""
    mock_enrich.return_value = {}  # empty = failure
    mock_enrich_is.return_value = ({}, False)  # failure

    from main import _enrich_results

    results = [{"ip": "8.8.8.8"}]
    error = asyncio.get_event_loop().run_until_complete(
        _enrich_results(results, enrich=True)
    )
    assert error is not None, "Expected error string when enrichment fails"
    assert "ip-api.com" in error or "ipapi.is" in error
