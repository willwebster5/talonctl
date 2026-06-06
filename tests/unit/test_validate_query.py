"""Tests for the talonctl validate-query CLI, focusing on template query resolution.

These exercise the --template path's resolution of the query string from both v1
flat-dict templates and v2 envelopes (apiVersion: talon/v2). The NGSIEMClient is
mocked so no API calls are made — we assert on which query reached the client.
"""

from unittest.mock import MagicMock, patch

from click.testing import CliRunner

from talonctl.cli import cli


def _run_with_template(tmp_path, filename, content):
    """Write `content` to tmp_path/filename and invoke validate-query --template on it.

    Returns (click result, query_string the mocked NGSIEMClient received).
    """
    template = tmp_path / filename
    template.write_text(content)

    captured = {}

    fake_client = MagicMock()

    def _test_query_syntax(q):
        captured["query"] = q
        return {"valid": True, "message": "ok"}

    fake_client.test_query_syntax.side_effect = _test_query_syntax

    runner = CliRunner()
    with patch("talonctl.utils.ngsiem_client.NGSIEMClient", return_value=fake_client):
        result = runner.invoke(cli, ["validate-query", "--template", str(template)])
    return result, captured.get("query")


def test_v1_saved_search_query_string(tmp_path):
    """v1 saved search: top-level queryString resolves and reaches the client."""
    content = "resource_id: ss_v1\nname: My v1 search\ntype: saved_search\nqueryString: 'foo | bar'\n"
    result, query = _run_with_template(tmp_path, "ss_v1.yaml", content)
    assert result.exit_code == 0, result.output
    assert "VALID" in result.output
    assert query == "foo | bar"


def test_v2_saved_search_spec_query_string(tmp_path):
    """v2 SavedSearch: query at spec.query_string resolves and reaches the client."""
    content = (
        "apiVersion: talon/v2\n"
        "kind: SavedSearch\n"
        "metadata:\n"
        "  resource_id: ss_v2\n"
        "  name: My v2 search\n"
        "spec:\n"
        "  query_string: 'baz | qux'\n"
    )
    result, query = _run_with_template(tmp_path, "ss_v2.yaml", content)
    assert result.exit_code == 0, result.output
    assert "VALID" in result.output
    assert query == "baz | qux"


def test_v1_detection_search_filter(tmp_path):
    """v1 detection: search.filter resolves and reaches the client."""
    content = "resource_id: det_v1\nname: My detection\ntype: detection\nsearch:\n  filter: 'event.type = login'\n"
    result, query = _run_with_template(tmp_path, "det_v1.yaml", content)
    assert result.exit_code == 0, result.output
    assert "VALID" in result.output
    assert query == "event.type = login"


def test_v1_detection_behavioral_subtype(tmp_path):
    """v1 detection with a realistic `type: behavioral` rule subtype.

    `behavioral` is the detection rule SUBTYPE, not a resource category, so it
    must be mapped to the "detection" resource type before reaching
    load_envelopes — otherwise TYPE_TO_KIND["behavioral"] raises KeyError and
    crashes this command. The search.filter must still be extracted and reach
    the mocked client.
    """
    content = (
        "resource_id: det_behavioral\n"
        "name: My behavioral detection\n"
        "type: behavioral\n"
        "search:\n"
        "  filter: 'event.type = login'\n"
    )
    result, query = _run_with_template(tmp_path, "det_behavioral.yaml", content)
    assert result.exit_code == 0, result.output
    assert "VALID" in result.output
    assert query == "event.type = login"


def test_v1_detection_correlation_subtype(tmp_path):
    """v1 detection with a realistic `type: correlation` rule subtype.

    Same KeyError-avoidance as the behavioral case: `correlation` is a rule
    subtype, must map to the "detection" resource type.
    """
    content = (
        "resource_id: det_correlation\n"
        "name: My correlation detection\n"
        "type: correlation\n"
        "search:\n"
        "  filter: 'event.type = alert'\n"
    )
    result, query = _run_with_template(tmp_path, "det_correlation.yaml", content)
    assert result.exit_code == 0, result.output
    assert "VALID" in result.output
    assert query == "event.type = alert"
