"""Tests for REST endpoint enrich_error propagation."""
import asyncio
from unittest.mock import patch

from ipdb import load_db

load_db()


@patch("main.enrich_with_ipapi")
@patch("main.enrich_with_ipapi_is")
def test_query_ips_includes_enrich_error_on_failure(mock_enrich_is, mock_enrich):
    """/api/query should include enrich_error when enrichment fails."""
    mock_enrich.return_value = {}  # empty = failure
    mock_enrich_is.return_value = ({}, False)  # failure

    from main import query_ips

    response = asyncio.get_event_loop().run_until_complete(
        query_ips({"ips": ["8.8.8.8"]}, enrich=True)
    )

    assert "enrich_error" in response, f"Missing enrich_error in response: {list(response.keys())}"
    assert response["enrich_error"] is not None
    assert "results" in response


@patch("main.enrich_with_ipapi")
@patch("main.enrich_with_ipapi_is")
def test_query_ips_no_error_when_not_enriching(mock_enrich_is, mock_enrich):
    """/api/query with enrich=False should have no enrich_error."""
    from main import query_ips

    response = asyncio.get_event_loop().run_until_complete(
        query_ips({"ips": ["8.8.8.8"]}, enrich=False)
    )

    # Should have enrich_error as None (or not present)
    error = response.get("enrich_error")
    assert error is None, f"Expected no error when not enriching, got: {error}"

    # External APIs should not be called
    mock_enrich.assert_not_called()
    mock_enrich_is.assert_not_called()
