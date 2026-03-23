"""
Shared CrowdStrike OAuth2 authentication and HTTP helpers.

Adapted from community fusion-workflows skill. Auth mechanism changed to read
credentials from ~/.config/falcon/credentials.json instead of .env files.

All other scripts import from this module. Run directly to verify credentials:

    python cs_auth.py
"""

import os
import sys
import json
import time
import requests

# Fix Windows console encoding
sys.stdout.reconfigure(encoding="utf-8", errors="replace")

# ── Base URL mapping ─────────────────────────────────────────────────────────

_BASE_URL_MAP = {
    "US1": "https://api.crowdstrike.com",
    "US2": "https://api.us-2.crowdstrike.com",
    "EU1": "https://api.eu-1.crowdstrike.com",
}


# ── Credentials ─────────────────────────────────────────────────────────────

def get_credentials(config_path=None):
    """Return (client_id, client_secret, base_url) from credentials JSON.

    Reads ~/.config/falcon/credentials.json and maps:
      - falcon_client_id   -> client_id
      - falcon_client_secret -> client_secret
      - base_url: short code (US1/US2/EU1) mapped to full URL,
                  or used as-is if already a full URL (starts with http)
    """
    if not config_path:
        config_path = os.path.join(os.path.expanduser("~"), ".config", "falcon", "credentials.json")

    if not os.path.isfile(config_path):
        print(f"ERROR: Credentials file not found: {config_path}", file=sys.stderr)
        sys.exit(1)

    try:
        with open(config_path, "r", encoding="utf-8") as f:
            config = json.load(f)
    except (json.JSONDecodeError, OSError) as e:
        print(f"ERROR: Failed to read credentials: {e}", file=sys.stderr)
        sys.exit(1)

    client_id = config.get("falcon_client_id", "")
    client_secret = config.get("falcon_client_secret", "")
    raw_base_url = config.get("base_url", "US1")

    if not client_id or not client_secret:
        print("ERROR: falcon_client_id and falcon_client_secret must be set in credentials.json", file=sys.stderr)
        sys.exit(1)

    # Map short codes to full URLs; use as-is if already a URL
    if raw_base_url.startswith("http"):
        base_url = raw_base_url.rstrip("/")
    else:
        base_url = _BASE_URL_MAP.get(raw_base_url.upper(), _BASE_URL_MAP["US1"])

    return client_id, client_secret, base_url


# ── Token cache ─────────────────────────────────────────────────────────────

_token_cache = {"token": None, "expires": 0}


def get_token(client_id=None, client_secret=None, base_url=None):
    """
    Obtain an OAuth2 bearer token via client_credentials grant.
    Caches the token until 60 s before expiry.
    """
    now = time.time()
    if _token_cache["token"] and now < _token_cache["expires"]:
        return _token_cache["token"]

    if client_id is None:
        client_id, client_secret, base_url = get_credentials()

    resp = requests.post(
        f"{base_url}/oauth2/token",
        data={
            "client_id": client_id,
            "client_secret": client_secret,
            "grant_type": "client_credentials",
        },
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    resp.raise_for_status()
    body = resp.json()

    _token_cache["token"] = body["access_token"]
    _token_cache["expires"] = now + body.get("expires_in", 1799) - 60
    return _token_cache["token"]


# ── HTTP helpers ────────────────────────────────────────────────────────────

def _base_url():
    _, _, url = get_credentials()
    return url


def _headers():
    return {"Authorization": f"Bearer {get_token()}"}


def api_get(path, params=None):
    """GET request with Bearer auth. Returns parsed JSON."""
    url = f"{_base_url()}{path}"
    resp = requests.get(url, headers=_headers(), params=params)
    resp.raise_for_status()
    return resp.json()


def api_post(path, json_body=None, params=None):
    """POST request with JSON body and Bearer auth. Returns parsed JSON."""
    url = f"{_base_url()}{path}"
    resp = requests.post(url, headers=_headers(), json=json_body, params=params)
    resp.raise_for_status()
    return resp.json()


def api_post_multipart(path, file_path, params=None):
    """
    POST multipart/form-data with a YAML file upload (field name 'data_file').
    Returns parsed JSON.
    """
    url = f"{_base_url()}{path}"
    filename = os.path.basename(file_path)
    with open(file_path, "rb") as f:
        files = {"data_file": (filename, f, "application/x-yaml")}
        resp = requests.post(url, headers=_headers(), files=files, params=params)
    resp.raise_for_status()
    return resp.json()


# ── Self-test ───────────────────────────────────────────────────────────────

def _mask(value, show_prefix=4, show_suffix=4):
    """Mask a sensitive string, showing only prefix/suffix."""
    if not value or len(value) < show_prefix + show_suffix + 4:
        return "********"
    return value[:show_prefix] + "..." + value[-show_suffix:]


if __name__ == "__main__":
    print("CrowdStrike Auth — self-test")
    print("─" * 40)
    cid, csec, burl = get_credentials()
    masked_id = _mask(cid, show_prefix=8)
    masked_secret = "********"
    print(f"  Base URL  : {burl}")
    print(f"  Client ID : {masked_id}")
    print(f"  Secret    : {masked_secret}")
    print()
    try:
        token = get_token(cid, csec, burl)
        masked_token = _mask(token, show_prefix=12)
        print(f"  Token     : {masked_token}")
        print("\n  Authentication successful")
    except Exception as e:
        print(f"\n  Authentication FAILED: {e}", file=sys.stderr)
        sys.exit(1)
