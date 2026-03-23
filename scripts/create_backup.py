#!/usr/bin/env python3
"""
Simple Backup System for CrowdStrike Detection State

Creates timestamped backups as GitHub releases for easy state restoration.
"""

import os
import json
import argparse
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, Optional, List
import zipfile
import tempfile
import shutil

class SimpleBackupSystem:
    """Creates and manages detection rule state backups using GitHub Releases"""
    
    def __init__(self, repo_path: str = "."):
        self.repo_path = Path(repo_path)
        self.state_dir = Path.cwd() / ".crowdstrike"
        self.backup_dir = self.state_dir / "backups"
        self.backup_dir.mkdir(parents=True, exist_ok=True)
        
    def create_backup(self, description: str = "Automated backup") -> bool:
        """Create a backup of current state and upload as GitHub release"""
        try:
            timestamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
            tag = f"backup-{timestamp}"
            
            print(f"📦 Creating backup: {tag}")
            
            # Create backup package
            backup_path = self._create_backup_package(timestamp)
            if not backup_path:
                return False
                
            # Create GitHub release
            if self._create_github_release(tag, description, backup_path):
                print(f"✅ Backup created successfully: {tag}")
                return True
            else:
                print("❌ Failed to create GitHub release")
                return False
                
        except Exception as e:
            print(f"❌ Backup failed: {e}")
            return False
    
    def _create_backup_package(self, timestamp: str) -> Optional[Path]:
        """Create a backup package with state files"""
        try:
            package_name = f"detection-backup-{timestamp}.zip"
            package_path = self.backup_dir / package_name
            
            with zipfile.ZipFile(package_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
                # Add state file
                state_file = self.state_dir / "deployed_state.json"
                if state_file.exists():
                    zipf.write(state_file, "deployed_state.json")
                    print(f"  📄 Added: deployed_state.json")
                
                # Add repository state file if it exists
                repo_state = self.repo_path / ".crowdstrike" / "deployed_state.json"
                if repo_state.exists():
                    zipf.write(repo_state, "repo_deployed_state.json")
                    print(f"  📄 Added: repo_deployed_state.json")
                
                # Add backup metadata
                metadata = {
                    "backup_timestamp": timestamp,
                    "backup_date": datetime.now(timezone.utc).isoformat(),
                    "git_commit": self._get_git_commit(),
                    "git_branch": self._get_git_branch(),
                    "state_version": self._get_state_version()
                }
                
                # Write metadata to temp file and add to zip
                with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
                    json.dump(metadata, f, indent=2)
                    temp_path = f.name
                
                zipf.write(temp_path, "backup_metadata.json")
                os.unlink(temp_path)
                print(f"  📄 Added: backup_metadata.json")
            
            print(f"📦 Backup package created: {package_path}")
            return package_path
            
        except Exception as e:
            print(f"❌ Failed to create backup package: {e}")
            return None
    
    def _create_github_release(self, tag: str, description: str, backup_path: Path) -> bool:
        """Create GitHub release with backup attachment"""
        try:
            # Check if gh CLI is available
            result = subprocess.run(["gh", "--version"], capture_output=True, text=True)
            if result.returncode != 0:
                print("❌ GitHub CLI (gh) not available - cannot create release")
                return False
            
            # Create release with backup file
            release_title = f"Detection State Backup - {tag}"
            release_body = f"""# Detection Rule State Backup

{description}

**Backup Information:**
- Timestamp: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}
- Git Commit: {self._get_git_commit() or 'unknown'}
- Git Branch: {self._get_git_branch() or 'unknown'}

## Restoration Instructions

To restore from this backup:

1. Download the backup file from this release
2. Extract the ZIP file
3. Copy `deployed_state.json` to `~/.crowdstrike/detection_state/deployed_state.json`
4. Run: `python scripts/detection_deploy.py apply --auto-approve`

Or use the automated restore command:
```bash
python scripts/create_backup.py restore {tag}
```

## Files in this backup
- `deployed_state.json`: Primary state file
- `repo_deployed_state.json`: Repository copy of state
- `backup_metadata.json`: Backup metadata and git information
"""
            
            cmd = [
                "gh", "release", "create", tag,
                str(backup_path),
                "--title", release_title,
                "--notes", release_body,
                "--prerelease"  # Mark as prerelease so it doesn't clutter main releases
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True, cwd=self.repo_path)
            
            if result.returncode == 0:
                print(f"✅ GitHub release created: {tag}")
                return True
            else:
                print(f"❌ Failed to create GitHub release: {result.stderr}")
                return False
                
        except Exception as e:
            print(f"❌ Failed to create GitHub release: {e}")
            return False
    
    def list_backups(self) -> List[str]:
        """List available backups from GitHub releases"""
        try:
            result = subprocess.run(
                ["gh", "release", "list", "--json", "tagName,createdAt,name"],
                capture_output=True, text=True, cwd=self.repo_path
            )
            
            if result.returncode != 0:
                print(f"❌ Failed to list releases: {result.stderr}")
                return []
            
            releases = json.loads(result.stdout)
            backups = [r for r in releases if r["tagName"].startswith("backup-")]
            
            if not backups:
                print("📦 No backups found")
                return []
            
            print("📦 Available backups:")
            for backup in sorted(backups, key=lambda x: x["createdAt"], reverse=True):
                tag = backup["tagName"]
                date = backup["createdAt"][:19].replace("T", " ")
                print(f"  • {tag} (created {date})")
            
            return [b["tagName"] for b in backups]
            
        except Exception as e:
            print(f"❌ Failed to list backups: {e}")
            return []
    
    def restore_backup(self, tag: str) -> bool:
        """Restore state from a backup release"""
        try:
            print(f"🔄 Restoring from backup: {tag}")
            
            # Download backup file
            with tempfile.TemporaryDirectory() as temp_dir:
                download_cmd = [
                    "gh", "release", "download", tag,
                    "--dir", temp_dir,
                    "--pattern", "*.zip"
                ]
                
                result = subprocess.run(download_cmd, capture_output=True, text=True, cwd=self.repo_path)
                if result.returncode != 0:
                    print(f"❌ Failed to download backup: {result.stderr}")
                    return False
                
                # Find and extract backup file
                zip_files = list(Path(temp_dir).glob("*.zip"))
                if not zip_files:
                    print("❌ No backup file found in release")
                    return False
                
                backup_zip = zip_files[0]
                extract_dir = Path(temp_dir) / "extract"
                extract_dir.mkdir()
                
                with zipfile.ZipFile(backup_zip, 'r') as zipf:
                    zipf.extractall(extract_dir)
                
                # Restore state file
                state_file = extract_dir / "deployed_state.json"
                if not state_file.exists():
                    print("❌ No deployed_state.json found in backup")
                    return False
                
                # Backup current state first
                current_state = self.state_dir / "deployed_state.json"
                if current_state.exists():
                    backup_current = self.state_dir / f"deployed_state.json.backup.{int(datetime.now().timestamp())}"
                    shutil.copy2(current_state, backup_current)
                    print(f"📄 Current state backed up to: {backup_current}")
                
                # Restore state
                shutil.copy2(state_file, current_state)
                print(f"✅ State restored from backup: {tag}")
                
                # Show metadata if available
                metadata_file = extract_dir / "backup_metadata.json"
                if metadata_file.exists():
                    with open(metadata_file) as f:
                        metadata = json.load(f)
                        print(f"📊 Backup metadata:")
                        print(f"  • Date: {metadata.get('backup_date', 'unknown')}")
                        print(f"  • Git commit: {metadata.get('git_commit', 'unknown')}")
                        print(f"  • Git branch: {metadata.get('git_branch', 'unknown')}")
                
                return True
                
        except Exception as e:
            print(f"❌ Restore failed: {e}")
            return False
    
    def _get_git_commit(self) -> Optional[str]:
        """Get current git commit hash"""
        try:
            result = subprocess.run(
                ["git", "rev-parse", "HEAD"], 
                capture_output=True, text=True, cwd=self.repo_path
            )
            return result.stdout.strip() if result.returncode == 0 else None
        except:
            return None
    
    def _get_git_branch(self) -> Optional[str]:
        """Get current git branch"""
        try:
            result = subprocess.run(
                ["git", "branch", "--show-current"],
                capture_output=True, text=True, cwd=self.repo_path
            )
            return result.stdout.strip() if result.returncode == 0 else None
        except:
            return None
    
    def _get_state_version(self) -> Optional[str]:
        """Get state file version"""
        try:
            state_file = self.state_dir / "deployed_state.json"
            if state_file.exists():
                with open(state_file) as f:
                    state = json.load(f)
                    return state.get("version", "unknown")
            return None
        except:
            return None

def main():
    parser = argparse.ArgumentParser(description="Simple backup system for detection state")
    subparsers = parser.add_subparsers(dest="command", help="Available commands")
    
    # Create backup
    create_parser = subparsers.add_parser("create", help="Create a new backup")
    create_parser.add_argument("--description", "-d", default="Automated backup",
                              help="Backup description")
    
    # List backups
    list_parser = subparsers.add_parser("list", help="List available backups")
    
    # Restore backup
    restore_parser = subparsers.add_parser("restore", help="Restore from backup")
    restore_parser.add_argument("tag", help="Backup tag to restore from")
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return
    
    backup_system = SimpleBackupSystem()
    
    if args.command == "create":
        backup_system.create_backup(args.description)
    elif args.command == "list":
        backup_system.list_backups()
    elif args.command == "restore":
        backup_system.restore_backup(args.tag)

if __name__ == "__main__":
    main()