"""talonctl discover — find new detection templates."""

import click

from talonctl.commands._common import console


@click.command()
@click.option("--vendors", type=str, help="Vendor filter (comma-separated)")
@click.option("--max-templates", type=int, default=100, help="Max templates to discover")
@click.pass_context
def discover(ctx, vendors, max_templates):
    """Discover new detection templates from the CrowdStrike template library."""
    console.print("[bold blue]Discovering templates...[/bold blue]\n")
    # TODO: Migrate full template_discovery logic to CLI
    console.print("[dim]Template discovery not yet migrated to CLI.[/dim]")
