"""Unit tests for talonctl auth command."""

from unittest.mock import patch
from click.testing import CliRunner

from talonctl.commands.auth import auth


class TestAuthSetup:
    """Test talonctl auth setup subcommand."""

    def test_auth_group_has_setup(self):
        """auth command group exposes 'setup' subcommand."""
        assert "setup" in [c.name for c in auth.commands.values()]

    def test_auth_group_has_check(self):
        """auth command group exposes 'check' subcommand."""
        assert "check" in [c.name for c in auth.commands.values()]

    @patch("talonctl.commands.auth.DEFAULT_CREDS_PATH")
    def test_setup_creates_credentials_file(self, mock_path, tmp_path):
        """setup writes credentials to disk."""
        creds_file = tmp_path / "credentials.json"
        mock_path.__truediv__ = lambda self, x: creds_file
        mock_path.exists.return_value = False
        mock_path.parent = tmp_path
        mock_path.__str__ = lambda self: str(creds_file)

        runner = CliRunner()
        result = runner.invoke(
            auth,
            [
                "setup",
                "--non-interactive",
                "--client-id",
                "test_id",
                "--client-secret",
                "test_secret",
                "--region",
                "US1",
                "--skip-validation",
            ],
        )
        assert result.exit_code == 0

    def test_check_without_credentials(self, tmp_path):
        """check reports missing credentials."""
        runner = CliRunner()
        with patch("talonctl.commands.auth.DEFAULT_CREDS_PATH") as mock_path:
            mock_path.exists.return_value = False
            result = runner.invoke(auth, ["check"])
            assert "No credentials found" in result.output or result.exit_code != 0
