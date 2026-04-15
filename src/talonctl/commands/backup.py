"""talonctl backup — create a state backup."""

import click

from talonctl.commands._common import console


@click.command()
@click.pass_context
def backup(ctx):
    """Create a backup of the current state file."""
    console.print("[bold blue]Creating backup...[/bold blue]\n")
    # TODO: Migrate backup logic to CLI
    console.print("[dim]Backup not yet migrated to CLI.[/dim]")
