"""Tests for make_health_query_fn — the adapter between NGSIEMClient and
DetectionHealthChecker's ngsiem_query_fn contract.

The checker calls fn(query=<cql>, time_range="Nd") and reads result.get("events").
NGSIEMClient.execute_query takes start_time (not time_range) and returns a
QueryResult dataclass (not a dict), so this adapter must bridge both.
"""

from unittest.mock import patch

from talonctl.utils.ngsiem_client import make_health_query_fn, QueryResult


def test_success_returns_events_dict():
    """Successful query yields a dict with the events list."""
    with patch("talonctl.utils.ngsiem_client.NGSIEMClient") as MockClient:
        MockClient.return_value.execute_query.return_value = QueryResult(
            success=True, events=[{"rule.name": "r", "_count": 3}]
        )
        fn = make_health_query_fn()
        out = fn(query="| limit 1", time_range="7d")

    assert out == {"events": [{"rule.name": "r", "_count": 3}]}


def test_time_range_is_mapped_to_start_time_kwarg():
    """The adapter must translate time_range -> start_time for execute_query."""
    with patch("talonctl.utils.ngsiem_client.NGSIEMClient") as MockClient:
        MockClient.return_value.execute_query.return_value = QueryResult(success=True, events=[])
        fn = make_health_query_fn()
        fn(query="cql", time_range="30d")

    MockClient.return_value.execute_query.assert_called_once_with("cql", start_time="30d")


def test_unsuccessful_query_returns_empty_events():
    """A failed (but non-raising) query degrades to empty events, not None."""
    with patch("talonctl.utils.ngsiem_client.NGSIEMClient") as MockClient:
        MockClient.return_value.execute_query.return_value = QueryResult(
            success=False, error="boom"
        )
        fn = make_health_query_fn()
        out = fn(query="cql", time_range="7d")

    assert out == {"events": []}


def test_auth_failure_degrades_gracefully():
    """If the client can't be constructed (e.g. no creds), return empty events."""
    with patch("talonctl.utils.ngsiem_client.NGSIEMClient", side_effect=RuntimeError("no creds")):
        fn = make_health_query_fn()
        out = fn(query="cql", time_range="7d")

    assert out == {"events": []}


def test_client_constructed_once_and_reused():
    """The client is built lazily and reused across calls."""
    with patch("talonctl.utils.ngsiem_client.NGSIEMClient") as MockClient:
        MockClient.return_value.execute_query.return_value = QueryResult(success=True, events=[])
        fn = make_health_query_fn()
        fn(query="a")
        fn(query="b")

    assert MockClient.call_count == 1
