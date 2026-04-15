"""Authentication utilities for FalconPy."""

import json
import os
from falconpy import APIHarnessV2, Hosts, Detects


def load_credentials(config_path=None):
    """Load CrowdStrike Falcon API credentials.

    Args:
        config_path: Optional explicit path to credentials file.
                    Defaults to ~/.config/falcon/credentials.json.

    Returns:
        Credentials dict or None if loading fails
    """
    if not config_path:
        config_path = os.path.join(os.path.expanduser("~/.config/falcon"), "credentials.json")

    try:
        with open(config_path, "r") as f:
            config = json.load(f)
        return config
    except Exception as e:
        print(f"Error loading credentials from {config_path}: {e}")
        return None


def get_uber_client():
    """Get an authenticated instance of the Uber Class."""
    config = load_credentials()
    if not config:
        return None

    return APIHarnessV2(
        client_id=config.get("falcon_client_id"),
        client_secret=config.get("falcon_client_secret"),
        base_url=config.get("base_url", "US1"),
    )


def get_hosts_client():
    """Get an authenticated instance of the Hosts Service Class."""
    config = load_credentials()
    if not config:
        return None

    return Hosts(
        client_id=config.get("falcon_client_id"),
        client_secret=config.get("falcon_client_secret"),
        base_url=config.get("base_url", "US1"),
    )


def get_detects_client():
    """Get an authenticated instance of the Detects Service Class."""
    config = load_credentials()
    if not config:
        return None

    return Detects(
        client_id=config.get("falcon_client_id"),
        client_secret=config.get("falcon_client_secret"),
        base_url=config.get("base_url", "US1"),
    )
