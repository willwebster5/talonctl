"""Tests for the talonctl validate CLI, including --queries."""

from unittest.mock import MagicMock, patch

from click.testing import CliRunner

from talonctl.cli import cli
from talonctl.core.deployment_orchestrator import QueryValidationResult


def _fake_orchestrator(validation_results=None, query_results=None, queries_raise=None):
    orch = MagicMock()
    orch.validate.return_value = validation_results or {}
    if queries_raise is not None:
        orch.validate_queries.side_effect = queries_raise
    else:
        orch.validate_queries.return_value = query_results or []
    return orch


def test_validate_schema_clean_no_queries_flag():
    runner = CliRunner()
    with patch("talonctl.commands.validate.init_orchestrator") as init_orch:
        init_orch.return_value = _fake_orchestrator(validation_results={"detection.a": []})
        result = runner.invoke(cli, ["validate"])
    assert result.exit_code == 0
    init_orch.return_value.validate_queries.assert_not_called()


def test_validate_schema_errors_short_circuit_before_queries():
    runner = CliRunner()
    with patch("talonctl.commands.validate.load_credentials", return_value={"falcon_client_id": "x"}):
        with patch("talonctl.commands.validate.init_orchestrator") as init_orch:
            init_orch.return_value = _fake_orchestrator(
                validation_results={"detection.a": ["missing field 'name'"]},
            )
            result = runner.invoke(cli, ["validate", "--queries"])
    assert result.exit_code == 1
    init_orch.return_value.validate_queries.assert_not_called()


def test_validate_queries_all_valid():
    runner = CliRunner()
    q_results = [
        QueryValidationResult(
            resource_id="detection.a",
            resource_name="a",
            is_valid=True,
            query_snippet="A",
            location="search.filter",
        ),
    ]
    with patch("talonctl.commands.validate.load_credentials", return_value={"falcon_client_id": "x"}):
        with patch("talonctl.commands.validate.init_orchestrator") as init_orch:
            init_orch.return_value = _fake_orchestrator(
                validation_results={"detection.a": []},
                query_results=q_results,
            )
            result = runner.invoke(cli, ["validate", "--queries"])
    assert result.exit_code == 0
    init_orch.return_value.validate_queries.assert_called_once()


def test_validate_queries_one_invalid_exits_nonzero():
    runner = CliRunner()
    q_results = [
        QueryValidationResult(
            resource_id="dashboard.d",
            resource_name="d",
            is_valid=False,
            error_message="LogScale rejected query (status=400, no detail returned by API)",
            query_snippet="bad |",
            location="widgets.w1.queryString",
        ),
    ]
    with patch("talonctl.commands.validate.load_credentials", return_value={"falcon_client_id": "x"}):
        with patch("talonctl.commands.validate.init_orchestrator") as init_orch:
            init_orch.return_value = _fake_orchestrator(
                validation_results={"dashboard.d": []},
                query_results=q_results,
            )
            result = runner.invoke(cli, ["validate", "--queries"])
    assert result.exit_code == 1
    assert "widgets.w1.queryString" in result.output


def test_validate_queries_ngsiem_client_value_error_maps_to_credentials_message():
    """NGSIEMClient raises ValueError (e.g. creds exist but invalid) -> friendly message."""
    runner = CliRunner()
    with patch("talonctl.commands.validate.load_credentials", return_value={"falcon_client_id": "x"}):
        with patch("talonctl.commands.validate.init_orchestrator") as init_orch:
            init_orch.return_value = _fake_orchestrator(
                validation_results={"detection.a": []},
                queries_raise=ValueError("Failed to load CrowdStrike credentials"),
            )
            result = runner.invoke(cli, ["validate", "--queries"])
    assert result.exit_code == 1
    assert "--queries requires configured credentials" in result.output
    assert "talonctl auth setup" in result.output


def test_validate_queries_no_credentials_file():
    """Real code path: load_credentials returns None -> documented message before init_orchestrator."""
    runner = CliRunner()
    with patch("talonctl.commands.validate.load_credentials", return_value=None) as mock_load:
        result = runner.invoke(cli, ["validate", "--queries"])
    assert result.exit_code == 1
    assert "--queries requires configured credentials" in result.output
    assert "talonctl auth setup" in result.output
    mock_load.assert_called_once()


def test_validate_queries_short_flag():
    runner = CliRunner()
    with patch("talonctl.commands.validate.load_credentials", return_value={"falcon_client_id": "x"}):
        with patch("talonctl.commands.validate.init_orchestrator") as init_orch:
            init_orch.return_value = _fake_orchestrator(
                validation_results={"detection.a": []},
                query_results=[],
            )
            result = runner.invoke(cli, ["validate", "-Q"])
    assert result.exit_code == 0
    init_orch.return_value.validate_queries.assert_called_once()
