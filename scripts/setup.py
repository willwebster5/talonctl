#!/usr/bin/env python3
"""
talonctl Setup Wizard

Interactive credential setup for the CrowdStrike Falcon API.
Validates the connection and saves credentials to ~/.config/falcon/credentials.json.

Usage:
    python scripts/setup.py
"""

import json
import os
import sys
from pathlib import Path
from getpass import getpass


# Default credential location
DEFAULT_CREDS_PATH = Path.home() / ".config" / "falcon" / "credentials.json"

# CrowdStrike cloud regions and their base URLs
CLOUD_REGIONS = {
    "US1": "https://api.crowdstrike.com/",
    "US2": "https://api.us-2.crowdstrike.com/",
    "EU1": "https://api.eu-1.crowdstrike.com/",
    "GOV1": "https://api.laggar.gcw.crowdstrike.com/",
}


def print_banner():
    """Print setup wizard banner"""
    print()
    print("=" * 60)
    print("  talonctl - Setup Wizard")
    print("=" * 60)
    print()
    print("This wizard will configure your CrowdStrike API credentials.")
    print(f"Credentials will be saved to: {DEFAULT_CREDS_PATH}")
    print()


def prompt_credentials():
    """Prompt user for API credentials"""
    print("Step 1: Enter API Credentials")
    print("-" * 40)
    print()
    print("You can find these in the Falcon Console under:")
    print("  Support & Resources > API Clients & Keys")
    print()

    client_id = input("  Client ID: ").strip()
    if not client_id:
        print("\nError: Client ID is required.")
        sys.exit(1)

    client_secret = getpass("  Client Secret: ").strip()
    if not client_secret:
        print("\nError: Client Secret is required.")
        sys.exit(1)

    print()
    print("Step 2: Select Cloud Region")
    print("-" * 40)
    print()
    for key, url in CLOUD_REGIONS.items():
        print(f"  {key}: {url}")
    print()

    base_url = input(f"  Cloud region [{', '.join(CLOUD_REGIONS.keys())}] (default: US1): ").strip().upper()
    if not base_url:
        base_url = "US1"
    if base_url not in CLOUD_REGIONS:
        print(f"\nError: Invalid region '{base_url}'. Must be one of: {', '.join(CLOUD_REGIONS.keys())}")
        sys.exit(1)

    return {
        "falcon_client_id": client_id,
        "falcon_client_secret": client_secret,
        "base_url": base_url
    }


def validate_credentials(creds):
    """Validate credentials by making a test API call"""
    print()
    print("Step 3: Validating Connection")
    print("-" * 40)
    print()

    try:
        from falconpy import APIHarnessV2

        print("  Connecting to CrowdStrike API...")
        falcon = APIHarnessV2(
            client_id=creds["falcon_client_id"],
            client_secret=creds["falcon_client_secret"],
            base_url=creds["base_url"]
        )

        # Test with a lightweight API call
        response = falcon.command("GetSensorInstallersCCIDByQuery")
        status = response.get("status_code", 0)

        if status == 200:
            print("  [OK] Authentication successful!")
            print(f"  [OK] Connected to {CLOUD_REGIONS.get(creds['base_url'], creds['base_url'])}")
            return True
        elif status == 403:
            print("  [WARNING] Authentication succeeded but API scope is limited.")
            print("  This is normal — credentials are valid but may lack some permissions.")
            print("  The setup will continue.")
            return True
        else:
            print(f"  [ERROR] API returned status {status}")
            print(f"  Response: {response}")
            return False

    except ImportError:
        print("  [WARNING] FalconPy not installed — skipping validation.")
        print("  Install with: pip install crowdstrike-falconpy")
        print("  Credentials will be saved without validation.")
        return True

    except Exception as e:
        print(f"  [ERROR] Connection failed: {e}")
        return False


def save_credentials(creds, path=None):
    """Save credentials to disk"""
    path = path or DEFAULT_CREDS_PATH

    print()
    print("Step 4: Saving Credentials")
    print("-" * 40)
    print()

    # Check for existing credentials
    if path.exists():
        overwrite = input(f"  Credentials file already exists at {path}.\n  Overwrite? [y/N]: ").strip().lower()
        if overwrite != 'y':
            print("  Cancelled — existing credentials preserved.")
            return False

    # Create directory
    path.parent.mkdir(parents=True, exist_ok=True)

    # Write credentials with restricted permissions
    with open(path, 'w') as f:
        json.dump(creds, f, indent=2)

    # Set file permissions to owner-only (600)
    os.chmod(path, 0o600)

    print(f"  [OK] Credentials saved to {path}")
    print(f"  [OK] File permissions set to 600 (owner-only)")

    return True


def print_next_steps():
    """Print helpful next steps"""
    print()
    print("=" * 60)
    print("  Setup Complete!")
    print("=" * 60)
    print()
    print("Next steps:")
    print()
    print("  1. Validate templates:")
    print("     python scripts/resource_deploy.py validate")
    print()
    print("  2. Import existing resources from CrowdStrike:")
    print("     python scripts/resource_deploy.py import --plan")
    print("     python scripts/resource_deploy.py import")
    print()
    print("  3. Plan a deployment (read-only):")
    print("     python scripts/resource_deploy.py plan")
    print()
    print("  4. Deploy changes:")
    print("     python scripts/resource_deploy.py apply")
    print()


def main():
    """Main setup wizard entry point"""
    print_banner()

    # Check for existing credentials
    if DEFAULT_CREDS_PATH.exists():
        try:
            with open(DEFAULT_CREDS_PATH) as f:
                existing = json.load(f)
            client_id = existing.get("falcon_client_id", "")
            masked_id = f"{client_id[:4]}...{client_id[-4:]}" if len(client_id) > 8 else "****"
            region = existing.get("base_url", "unknown")
            print(f"Existing credentials found:")
            print(f"  Client ID: {masked_id}")
            print(f"  Region: {region}")
            print()
            reconfigure = input("Reconfigure? [y/N]: ").strip().lower()
            if reconfigure != 'y':
                print("\nKeeping existing credentials.")
                print_next_steps()
                return 0
        except Exception:
            pass

    # Prompt for credentials
    creds = prompt_credentials()

    # Validate
    valid = validate_credentials(creds)
    if not valid:
        retry = input("\n  Validation failed. Save credentials anyway? [y/N]: ").strip().lower()
        if retry != 'y':
            print("\n  Setup cancelled.")
            return 1

    # Save
    saved = save_credentials(creds)
    if not saved:
        return 1

    print_next_steps()
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n\nSetup cancelled by user.")
        sys.exit(130)
