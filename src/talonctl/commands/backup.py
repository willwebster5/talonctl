"""talonctl backup — state backup and restore via GitHub Releases."""

import os
import json
import subprocess
import shutil
import tempfile
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, List

import click

from talonctl.commands._common import console
from talonctl.project import find_project_root


class SimpleBackupSystem:
    """Creates and manages detection rule state backups using GitHub Releases."""

    def __init__(self, repo_path: str = "."):
        self.repo_path = Path(repo_path)
        self.state_dir = find_project_root() / ".crowdstrike"
        self.backup_dir = self.state_dir / "backups"
        self.backup_dir.mkdir(parents=True, exist_ok=True)

    def create_backup(self, description: str = "Automated backup") -> bool:
        """Create a backup of current state and upload as GitHub release."""
        try:
            timestamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
            tag = f"backup-{timestamp}"

            console.print(f"Creating backup: [bold]{tag}[/bold]")

            # Create backup package
            backup_path = self._create_backup_package(timestamp)
            if not backup_path:
                return False

            # Create GitHub release
            if self._create_github_release(tag, description, backup_path):
                console.print(f"[green]Backup created successfully: {tag}[/green]")
                return True
            else:
                console.print("[red]Failed to create GitHub release[/red]")
                return False

        except Exception as e:
            console.print(f"[red]Backup failed: {e}[/red]")
            return False

    def _create_backup_package(self, timestamp: str) -> Optional[Path]:
        """Create a backup package with state files."""
        try:
            package_name = f"detection-backup-{timestamp}.zip"
            package_path = self.backup_dir / package_name

            with zipfile.ZipFile(package_path, "w", zipfile.ZIP_DEFLATED) as zipf:
                # Add state file
                state_file = self.state_dir / "deployed_state.json"
                if state_file.exists():
                    zipf.write(state_file, "deployed_state.json")
                    console.print("  Added: deployed_state.json")

                # Add repository state file if it exists
                repo_state = self.repo_path / ".crowdstrike" / "deployed_state.json"
                if repo_state.exists():
                    zipf.write(repo_state, "repo_deployed_state.json")
                    console.print("  Added: repo_deployed_state.json")

                # Add backup metadata
                metadata = {
                    "backup_timestamp": timestamp,
                    "backup_date": datetime.now(timezone.utc).isoformat(),
                    "git_commit": self._get_git_commit(),
                    "git_branch": self._get_git_branch(),
                    "state_version": self._get_state_version(),
                }

                # Write metadata to temp file and add to zip
                with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
                    json.dump(metadata, f, indent=2)
                    temp_path = f.name

                zipf.write(temp_path, "backup_metadata.json")
                os.unlink(temp_path)
                console.print("  Added: backup_metadata.json")

            console.print(f"Backup package created: {package_path}")
            return package_path

        except Exception as e:
            console.print(f"[red]Failed to create backup package: {e}[/red]")
            return None

    def _create_github_release(self, tag: str, description: str, backup_path: Path) -> bool:
        """Create GitHub release with backup attachment."""
        try:
            # Check if gh CLI is available
            result = subprocess.run(["gh", "--version"], capture_output=True, text=True)
            if result.returncode != 0:
                console.print("[red]GitHub CLI (gh) not available -- cannot create release[/red]")
                return False

            # Create release with backup file
            release_title = f"Detection State Backup - {tag}"
            release_body = f"""# Detection Rule State Backup

{description}

**Backup Information:**
- Timestamp: {datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")}
- Git Commit: {self._get_git_commit() or "unknown"}
- Git Branch: {self._get_git_branch() or "unknown"}

## Restoration Instructions

To restore from this backup:

```bash
talonctl backup restore {tag}
```
"""

            cmd = [
                "gh",
                "release",
                "create",
                tag,
                str(backup_path),
                "--title",
                release_title,
                "--notes",
                release_body,
                "--prerelease",
            ]

            result = subprocess.run(cmd, capture_output=True, text=True, cwd=self.repo_path)

            if result.returncode == 0:
                console.print(f"[green]GitHub release created: {tag}[/green]")
                return True
            else:
                console.print(f"[red]Failed to create GitHub release: {result.stderr}[/red]")
                return False

        except Exception as e:
            console.print(f"[red]Failed to create GitHub release: {e}[/red]")
            return False

    def list_backups(self) -> List[str]:
        """List available backups from GitHub releases."""
        try:
            result = subprocess.run(
                ["gh", "release", "list", "--json", "tagName,createdAt,name"],
                capture_output=True,
                text=True,
                cwd=self.repo_path,
            )

            if result.returncode != 0:
                console.print(f"[red]Failed to list releases: {result.stderr}[/red]")
                return []

            releases = json.loads(result.stdout)
            backups = [r for r in releases if r["tagName"].startswith("backup-")]

            if not backups:
                console.print("No backups found")
                return []

            console.print("[bold]Available backups:[/bold]")
            for b in sorted(backups, key=lambda x: x["createdAt"], reverse=True):
                tag = b["tagName"]
                date = b["createdAt"][:19].replace("T", " ")
                console.print(f"  {tag} (created {date})")

            return [b["tagName"] for b in backups]

        except Exception as e:
            console.print(f"[red]Failed to list backups: {e}[/red]")
            return []

    def restore_backup(self, tag: str) -> bool:
        """Restore state from a backup release."""
        try:
            console.print(f"Restoring from backup: [bold]{tag}[/bold]")

            # Download backup file
            with tempfile.TemporaryDirectory() as temp_dir:
                download_cmd = ["gh", "release", "download", tag, "--dir", temp_dir, "--pattern", "*.zip"]

                result = subprocess.run(download_cmd, capture_output=True, text=True, cwd=self.repo_path)
                if result.returncode != 0:
                    console.print(f"[red]Failed to download backup: {result.stderr}[/red]")
                    return False

                # Find and extract backup file
                zip_files = list(Path(temp_dir).glob("*.zip"))
                if not zip_files:
                    console.print("[red]No backup file found in release[/red]")
                    return False

                backup_zip = zip_files[0]
                extract_dir = Path(temp_dir) / "extract"
                extract_dir.mkdir()

                with zipfile.ZipFile(backup_zip, "r") as zipf:
                    zipf.extractall(extract_dir)

                # Restore state file
                state_file = extract_dir / "deployed_state.json"
                if not state_file.exists():
                    console.print("[red]No deployed_state.json found in backup[/red]")
                    return False

                # Backup current state first
                current_state = self.state_dir / "deployed_state.json"
                if current_state.exists():
                    backup_current = self.state_dir / f"deployed_state.json.backup.{int(datetime.now().timestamp())}"
                    shutil.copy2(current_state, backup_current)
                    console.print(f"Current state backed up to: {backup_current}")

                # Restore state
                shutil.copy2(state_file, current_state)
                console.print(f"[green]State restored from backup: {tag}[/green]")

                # Show metadata if available
                metadata_file = extract_dir / "backup_metadata.json"
                if metadata_file.exists():
                    with open(metadata_file) as f:
                        metadata = json.load(f)
                        console.print("Backup metadata:")
                        console.print(f"  Date: {metadata.get('backup_date', 'unknown')}")
                        console.print(f"  Git commit: {metadata.get('git_commit', 'unknown')}")
                        console.print(f"  Git branch: {metadata.get('git_branch', 'unknown')}")

                return True

        except Exception as e:
            console.print(f"[red]Restore failed: {e}[/red]")
            return False

    def _get_git_commit(self) -> Optional[str]:
        """Get current git commit hash."""
        try:
            result = subprocess.run(["git", "rev-parse", "HEAD"], capture_output=True, text=True, cwd=self.repo_path)
            return result.stdout.strip() if result.returncode == 0 else None
        except Exception:
            return None

    def _get_git_branch(self) -> Optional[str]:
        """Get current git branch."""
        try:
            result = subprocess.run(
                ["git", "branch", "--show-current"], capture_output=True, text=True, cwd=self.repo_path
            )
            return result.stdout.strip() if result.returncode == 0 else None
        except Exception:
            return None

    def _get_state_version(self) -> Optional[str]:
        """Get state file version."""
        try:
            state_file = self.state_dir / "deployed_state.json"
            if state_file.exists():
                with open(state_file) as f:
                    state = json.load(f)
                    return state.get("version", "unknown")
            return None
        except Exception:
            return None


@click.group()
def backup():
    """Manage state backups via GitHub Releases."""
    pass


@backup.command()
@click.option("--description", "-d", default="Automated backup", help="Backup description")
def create(description):
    """Create a new state backup."""
    console.print("[bold cyan]talonctl backup create[/bold cyan]\n")
    system = SimpleBackupSystem()
    success = system.create_backup(description)
    if not success:
        raise SystemExit(1)


@backup.command("list")
def list_backups():
    """List available backups."""
    console.print("[bold cyan]talonctl backup list[/bold cyan]\n")
    system = SimpleBackupSystem()
    system.list_backups()


@backup.command()
@click.argument("tag")
def restore(tag):
    """Restore state from a backup tag."""
    console.print(f"[bold cyan]talonctl backup restore {tag}[/bold cyan]\n")
    system = SimpleBackupSystem()
    success = system.restore_backup(tag)
    if not success:
        raise SystemExit(1)
