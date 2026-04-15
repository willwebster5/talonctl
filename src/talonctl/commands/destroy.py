"""talonctl destroy — remove specified resources."""

import click

from talonctl.commands._common import console


@click.command()
@click.pass_context
def destroy(ctx):
    """Remove specified resources from CrowdStrike."""
    console.print("[bold red]Destroying resources...[/bold red]\n")
    console.print("[yellow]⚠ Destroy command not yet implemented[/yellow]\n")
    console.print("This feature will remove resources from CrowdStrike.\n")
