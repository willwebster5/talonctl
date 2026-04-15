"""talonctl publish — activate inactive detection rules."""

import click
from rich.prompt import Confirm

from talonctl.commands._common import (
    console,
    filter_options,
    state_options,
    parse_filters,
)


@click.command()
@filter_options
@state_options
@click.option("--auto-approve", is_flag=True, help="Skip confirmation prompts")
@click.pass_context
def publish(ctx, resources, tags, names, state_file, auto_approve):
    """Activate inactive detection rules for production."""
    console.print("[bold blue]Publishing detection rules...[/bold blue]\n")
    verbose = ctx.obj.get("verbose", False)

    filters = parse_filters(resources, tags, names)

    try:
        from talonctl.providers import DetectionProvider
        from talonctl.utils.auth import load_credentials
        from falconpy import APIHarnessV2

        creds = load_credentials()
        falcon = APIHarnessV2(
            client_id=creds["falcon_client_id"],
            client_secret=creds["falcon_client_secret"],
            base_url=creds.get("base_url", "US1"),
        )

        detection_provider = DetectionProvider(falcon_client=falcon)

        resource_ids = None
        if filters.get("names"):
            resource_ids = [f"detection.{name}" for name in filters["names"]]

        console.print("[cyan]Finding inactive detection rules to publish...[/cyan]\n")

        successful, failed = detection_provider.publish(resource_ids=resource_ids)

        total = len(successful) + len(failed)
        if total == 0:
            console.print("[yellow]No inactive detection rules found to publish[/yellow]\n")
            return

        console.print(f"[bold]Found {total} inactive detection rule(s):[/bold]")
        for resource_id in successful + [f for f, _ in failed]:
            rule_name = resource_id.split(".", 1)[1] if "." in resource_id else resource_id
            console.print(f"  • {rule_name}")
        console.print()

        if not auto_approve:
            if not Confirm.ask("[yellow]Do you want to activate these rules for production?[/yellow]"):
                console.print("\n[dim]Publish cancelled.[/dim]\n")
                return

        if successful:
            console.print(f"\n[green]✓ Successfully activated {len(successful)} detection rule(s)[/green]")
            for resource_id in successful:
                rule_name = resource_id.split(".", 1)[1] if "." in resource_id else resource_id
                console.print(f"  • {rule_name}")
            console.print()

        if failed:
            console.print(f"\n[red]✗ Failed to activate {len(failed)} detection rule(s)[/red]")
            for resource_id, error in failed:
                rule_name = resource_id.split(".", 1)[1] if "." in resource_id else resource_id
                console.print(f"  • {rule_name}: {error}")
            console.print()

        if failed:
            raise SystemExit(1)

    except SystemExit:
        raise
    except Exception as e:
        console.print(f"[red]✗ Error during publish: {e}[/red]")
        if verbose:
            import traceback

            traceback.print_exc()
        raise SystemExit(1)
