"""Unit tests for talonctl backup command."""

from unittest.mock import patch
from click.testing import CliRunner

from talonctl.commands.backup import backup


class TestBackupCommand:
    """Test talonctl backup CLI integration."""

    def test_backup_group_has_create(self):
        assert "create" in [c.name for c in backup.commands.values()]

    def test_backup_group_has_list(self):
        assert "list" in [c.name for c in backup.commands.values()]

    def test_backup_group_has_restore(self):
        assert "restore" in [c.name for c in backup.commands.values()]

    @patch("talonctl.commands.backup.SimpleBackupSystem")
    def test_create_invokes_backup(self, MockSystem):
        """create subcommand calls SimpleBackupSystem.create_backup."""
        MockSystem.return_value.create_backup.return_value = True
        runner = CliRunner()
        result = runner.invoke(backup, ["create"])
        assert result.exit_code == 0
        MockSystem.return_value.create_backup.assert_called_once()

    @patch("talonctl.commands.backup.SimpleBackupSystem")
    def test_list_invokes_list(self, MockSystem):
        """list subcommand calls SimpleBackupSystem.list_backups."""
        MockSystem.return_value.list_backups.return_value = []
        runner = CliRunner()
        result = runner.invoke(backup, ["list"])
        assert result.exit_code == 0

    @patch("talonctl.commands.backup.SimpleBackupSystem")
    def test_restore_requires_tag(self, MockSystem):
        """restore requires a tag argument."""
        runner = CliRunner()
        result = runner.invoke(backup, ["restore"])
        assert result.exit_code != 0
