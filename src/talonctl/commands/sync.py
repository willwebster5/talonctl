"""talonctl sync — synchronize state with CrowdStrike."""

import click

from talonctl.commands._common import (
    console,
    filter_options,
    state_options,
    parse_filters,
    init_orchestrator,
)


@click.command()
@filter_options
@state_options
@click.pass_context
def sync(ctx, resources, tags, names, state_file):
    """Synchronize state with CrowdStrike."""
    console.print("[bold blue]Synchronizing state with CrowdStrike...[/bold blue]\n")
    console.print("[cyan]Fetching currently deployed resources from CrowdStrike API...[/cyan]\n")
    verbose = ctx.obj.get("verbose", False)

    orchestrator = init_orchestrator(state_file=state_file)
    filters = parse_filters(resources, tags, names)

    try:
        stats = orchestrator.sync(**filters)

        console.print("\n[bold]Sync Results:[/bold]")
        console.print(f"  [cyan]Total fetched:[/cyan] {stats['total_fetched']}")
        console.print(f"  [green]Matched templates:[/green] {stats['matched_templates']}")
        console.print(f"  [yellow]Unmatched (no template):[/yellow] {stats['unmatched']}")
        console.print(f"  [blue]State updated:[/blue] {stats['updated']}")

        stale_removed = stats.get("stale_removed", 0)
        if stale_removed > 0:
            console.print(f"  [magenta]Stale state removed:[/magenta] {stale_removed}")

        console.print()

        stale_names = stats.get("stale_names", [])
        if stale_names:
            console.print(
                f"[magenta]Removed {len(stale_names)} stale state entries (no template, no remote resource):[/magenta]"
            )
            display_limit = 20
            for name in stale_names[:display_limit]:
                console.print(f"  [magenta]![/magenta] {name}")
            if len(stale_names) > display_limit:
                console.print(f"  [dim]... and {len(stale_names) - display_limit} more[/dim]")
            console.print()

        if stats["unmatched"] > 0:
            console.print(f"[yellow]⚠ {stats['unmatched']} deployed resource(s) have no matching IaC template[/yellow]")
            unmatched_names = stats.get("unmatched_names", [])
            if unmatched_names:
                display_limit = 20
                for name in unmatched_names[:display_limit]:
                    console.print(f"  [yellow]?[/yellow] {name}")
                if len(unmatched_names) > display_limit:
                    console.print(f"  [dim]... and {len(unmatched_names) - display_limit} more[/dim]")
            console.print(
                "[dim]These resources are not tracked in state (IaC only manages resources with templates)[/dim]\n"
            )

        if stats["matched_templates"] > 0:
            console.print(f"[green]✓ State synchronized with {stats['matched_templates']} resources[/green]\n")
        else:
            console.print(
                "[yellow]No resources synced - check filters or verify resources exist in CrowdStrike[/yellow]\n"
            )

    except SystemExit:
        raise
    except Exception as e:
        console.print(f"[red]✗ Error during sync: {e}[/red]")
        if verbose:
            import traceback

            traceback.print_exc()
        raise SystemExit(1)
