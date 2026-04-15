"""talonctl auth — credential setup and validation."""

import json
import os
from pathlib import Path

import click

from talonctl.commands._common import console

DEFAULT_CREDS_PATH = Path.home() / ".config" / "falcon" / "credentials.json"

CLOUD_REGIONS = {
    "US1": "https://api.crowdstrike.com/",
    "US2": "https://api.us-2.crowdstrike.com/",
    "EU1": "https://api.eu-1.crowdstrike.com/",
    "GOV1": "https://api.laggar.gcw.crowdstrike.com/",
}


@click.group()
def auth():
    """Manage CrowdStrike API credentials."""
    pass


@auth.command()
@click.option("--non-interactive", is_flag=True, help="Non-interactive mode (requires --client-id and --client-secret)")
@click.option("--client-id", type=str, help="CrowdStrike API client ID")
@click.option("--client-secret", type=str, help="CrowdStrike API client secret")
@click.option(
    "--region",
    type=click.Choice(list(CLOUD_REGIONS.keys()), case_sensitive=False),
    default="US1",
    help="CrowdStrike cloud region",
)
@click.option("--skip-validation", is_flag=True, help="Skip API connection validation")
@click.option("--force", is_flag=True, help="Overwrite existing credentials without prompting")
def setup(non_interactive, client_id, client_secret, region, skip_validation, force):
    """Set up CrowdStrike API credentials."""
    console.print("[bold cyan]talonctl auth setup[/bold cyan]\n")

    if DEFAULT_CREDS_PATH.exists() and not force:
        try:
            existing = json.loads(DEFAULT_CREDS_PATH.read_text())
            cid = existing.get("falcon_client_id", "")
            masked = f"{cid[:4]}...{cid[-4:]}" if len(cid) > 8 else "****"
            console.print(
                f"Existing credentials found: Client ID [bold]{masked}[/bold], Region [bold]{existing.get('base_url', 'unknown')}[/bold]"
            )
            if not non_interactive:
                if not click.confirm("Overwrite?", default=False):
                    console.print("[dim]Keeping existing credentials.[/dim]")
                    return
        except Exception:
            pass

    if non_interactive:
        if not client_id or not client_secret:
            raise click.UsageError("--client-id and --client-secret required in --non-interactive mode")
    else:
        console.print("Enter your CrowdStrike API credentials.")
        console.print("[dim]Find these at: Falcon Console > Support & Resources > API Clients & Keys[/dim]\n")
        client_id = click.prompt("Client ID")
        client_secret = click.prompt("Client Secret", hide_input=True)
        region = click.prompt(
            "Cloud region", type=click.Choice(list(CLOUD_REGIONS.keys()), case_sensitive=False), default="US1"
        )

    creds = {
        "falcon_client_id": client_id,
        "falcon_client_secret": client_secret,
        "base_url": region.upper(),
    }

    if not skip_validation:
        _validate_credentials(creds)

    DEFAULT_CREDS_PATH.parent.mkdir(parents=True, exist_ok=True)
    DEFAULT_CREDS_PATH.write_text(json.dumps(creds, indent=2))
    os.chmod(DEFAULT_CREDS_PATH, 0o600)

    console.print(f"\n[green]Credentials saved to {DEFAULT_CREDS_PATH}[/green]")
    console.print("[dim]File permissions set to 600 (owner-only)[/dim]")


@auth.command()
def check():
    """Verify stored credentials are valid."""
    console.print("[bold cyan]talonctl auth check[/bold cyan]\n")

    if not DEFAULT_CREDS_PATH.exists():
        console.print("[red]No credentials found.[/red]")
        console.print(f"[dim]Expected at: {DEFAULT_CREDS_PATH}[/dim]")
        console.print("Run [bold]talonctl auth setup[/bold] to configure.")
        raise SystemExit(1)

    creds = json.loads(DEFAULT_CREDS_PATH.read_text())
    cid = creds.get("falcon_client_id", "")
    masked = f"{cid[:4]}...{cid[-4:]}" if len(cid) > 8 else "****"
    console.print(f"Client ID: [bold]{masked}[/bold]")
    console.print(f"Region:    [bold]{creds.get('base_url', 'unknown')}[/bold]")

    _validate_credentials(creds)


def _validate_credentials(creds):
    """Validate credentials by making a test API call."""
    try:
        from falconpy import APIHarnessV2

        console.print("Connecting to CrowdStrike API...")
        falcon = APIHarnessV2(
            client_id=creds["falcon_client_id"],
            client_secret=creds["falcon_client_secret"],
            base_url=creds["base_url"],
        )
        response = falcon.command("GetSensorInstallersCCIDByQuery")
        status = response.get("status_code", 0)

        if status == 200:
            console.print("[green]Authentication successful.[/green]")
        elif status == 403:
            console.print("[yellow]Authentication succeeded but API scope is limited (normal).[/yellow]")
        else:
            console.print(f"[red]API returned status {status}[/red]")
            raise SystemExit(1)
    except ImportError:
        console.print("[yellow]FalconPy not installed -- skipping validation.[/yellow]")
    except SystemExit:
        raise
    except Exception as e:
        console.print(f"[red]Connection failed: {e}[/red]")
        raise SystemExit(1)
