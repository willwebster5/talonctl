"""talonctl import — import existing CrowdStrike resources."""

import click

from talonctl.commands._common import (
    console,
    filter_options,
    state_options,
    parse_filters,
    init_orchestrator,
)


@click.command("import_cmd")
@filter_options
@state_options
@click.option("--plan", "import_plan", is_flag=True, help="Dry-run: show what would be imported")
@click.pass_context
def import_cmd(ctx, resources, tags, names, state_file, import_plan):
    """Import existing CrowdStrike resources as YAML templates."""
    if import_plan:
        console.print("[bold blue]Import plan (dry-run)...[/bold blue]\n")
    else:
        console.print("[bold blue]Importing resources from CrowdStrike...[/bold blue]\n")
    verbose = ctx.obj.get("verbose", False)

    orchestrator = init_orchestrator(state_file=state_file)
    filters = parse_filters(resources, tags, names)

    try:
        stats = orchestrator.import_resources(
            resource_types=filters.get("resource_types"), names=filters.get("names"), plan_only=import_plan
        )

        console.print("\n[bold]Import Results:[/bold]")
        console.print(f"  [cyan]Total fetched from API:[/cyan] {stats['total_fetched']}")
        console.print(f"  [green]{'Would import' if import_plan else 'Imported'}:[/green] {stats['imported']}")
        console.print(f"  [yellow]Skipped (already exist):[/yellow] {stats['skipped_existing']}")
        if stats["skipped_unsupported"] > 0:
            console.print(f"  [dim]Skipped (unsupported):[/dim] {stats['skipped_unsupported']}")
        console.print()

        if stats["imported_files"]:
            action = "Would write" if import_plan else "Wrote"
            console.print(f"[bold]{action} {len(stats['imported_files'])} template files:[/bold]")
            display_limit = 30
            for f in stats["imported_files"][:display_limit]:
                prefix = "[dim]+[/dim]" if import_plan else "[green]+[/green]"
                console.print(f"  {prefix} resources/{f}")
            if len(stats["imported_files"]) > display_limit:
                console.print(f"  [dim]... and {len(stats['imported_files']) - display_limit} more[/dim]")
            console.print()

        if stats["errors"]:
            console.print(f"[red]Errors ({len(stats['errors'])}):[/red]")
            for error in stats["errors"][:10]:
                console.print(f"  [red]![/red] {error}")
            if len(stats["errors"]) > 10:
                console.print(f"  [dim]... and {len(stats['errors']) - 10} more[/dim]")
            console.print()

        if stats["imported"] > 0 and not import_plan:
            console.print(f"[green]✓ Successfully imported {stats['imported']} resources as YAML templates[/green]\n")
        elif stats["imported"] > 0 and import_plan:
            console.print(f"[cyan]→ Run without --plan to import {stats['imported']} resources[/cyan]\n")
        elif stats["imported"] == 0 and stats["skipped_existing"] > 0:
            console.print("[yellow]All matching resources already have template files — nothing to import[/yellow]\n")
        else:
            console.print("[yellow]No resources found to import[/yellow]\n")

        if stats["errors"]:
            ctx.exit(1)

    except Exception as e:
        console.print(f"[red]✗ Error during import: {e}[/red]")
        if verbose:
            import traceback

            traceback.print_exc()
        ctx.exit(1)
