"""talonctl CLI — Infrastructure as code for CrowdStrike NGSIEM."""

import logging
from datetime import datetime

import click

from talonctl import __version__
from talonctl.commands._common import console


@click.group()
@click.version_option(version=__version__, prog_name="talonctl")
@click.option('--verbose', '-v', is_flag=True, help='Enable verbose output')
@click.pass_context
def cli(ctx, verbose):
    """Infrastructure as code for CrowdStrike NGSIEM."""
    ctx.ensure_object(dict)
    ctx.obj['verbose'] = verbose

    if verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    )

    console.print(f"\n[bold cyan]talonctl[/bold cyan] [dim]v{__version__}[/dim]")
    console.print(f"[dim]{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}[/dim]\n")


# Import and register command modules
from talonctl.commands.validate import validate  # noqa: E402
from talonctl.commands.plan import plan  # noqa: E402
from talonctl.commands.apply import apply  # noqa: E402
from talonctl.commands.show import show  # noqa: E402
from talonctl.commands.sync import sync  # noqa: E402
from talonctl.commands.drift import drift  # noqa: E402
from talonctl.commands.destroy import destroy  # noqa: E402
from talonctl.commands.import_cmd import import_cmd  # noqa: E402
from talonctl.commands.publish import publish  # noqa: E402
from talonctl.commands.validate_query import validate_query  # noqa: E402
from talonctl.commands.init import init  # noqa: E402
from talonctl.commands.discover import discover  # noqa: E402
from talonctl.commands.backup import backup  # noqa: E402

cli.add_command(validate)
cli.add_command(plan)
cli.add_command(apply)
cli.add_command(show)
cli.add_command(sync)
cli.add_command(drift)
cli.add_command(destroy)
cli.add_command(import_cmd, name='import')
cli.add_command(publish)
cli.add_command(validate_query, name='validate-query')
cli.add_command(init)
cli.add_command(discover)
cli.add_command(backup)
