"""talonctl CLI — Infrastructure as code for CrowdStrike NGSIEM."""

import logging
from datetime import datetime

import click

from talonctl import __version__
from talonctl.commands._common import console

_BANNER_SUPPRESS_KEY = "talonctl.suppress_banner"


class _TalonGroup(click.Group):
    """Click Group subclass that peeks at subcommand args to suppress the
    banner when ``find`` is invoked with ``--format json`` or ``--format path``.
    The peek happens in ``invoke()`` before the group callback fires so that
    ``ctx.meta`` carries the flag by the time the callback checks it.
    Works under ``CliRunner`` (does NOT use ``sys.argv``).
    """

    def invoke(self, ctx: click.Context) -> object:
        # At invoke() time in Click 8, ctx.invoked_subcommand is not yet set.
        # ctx.protected_args holds the subcommand name token; ctx.args holds
        # the subcommand's remaining args (NOT sys.argv — works under CliRunner).
        sub_cmd = (list(ctx.protected_args) + list(ctx.args))[:1]
        sub_args = list(ctx.args) if ctx.protected_args else list(ctx.args[1:])
        if sub_cmd and sub_cmd[0] == "find":
            for i, token in enumerate(sub_args):
                if token == "--format" and i + 1 < len(sub_args):
                    if sub_args[i + 1] in ("json", "path"):
                        ctx.meta[_BANNER_SUPPRESS_KEY] = True
                    break
                if token.startswith("--format="):
                    val = token.split("=", 1)[1]
                    if val in ("json", "path"):
                        ctx.meta[_BANNER_SUPPRESS_KEY] = True
                    break
        return super().invoke(ctx)


@click.group(cls=_TalonGroup)
@click.version_option(version=__version__, prog_name="talonctl")
@click.option("--verbose", "-v", is_flag=True, help="Enable verbose output")
@click.pass_context
def cli(ctx, verbose):
    """Infrastructure as code for CrowdStrike NGSIEM."""
    ctx.ensure_object(dict)
    ctx.obj["verbose"] = verbose

    if verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )

    # Suppress banner for machine-readable `find` output so stdout pipes cleanly.
    # The _TalonGroup.invoke() sets this flag via ctx.meta before this callback
    # fires, so ctx.args is not needed here (it is empty by callback time in
    # Click 8).
    if not ctx.meta.get(_BANNER_SUPPRESS_KEY, False):
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
from talonctl.commands.auth import auth  # noqa: E402
from talonctl.commands.health import health  # noqa: E402
from talonctl.commands.metrics import metrics  # noqa: E402
from talonctl.commands.find import find  # noqa: E402
from talonctl.commands.migrate import migrate  # noqa: E402

cli.add_command(validate)
cli.add_command(plan)
cli.add_command(apply)
cli.add_command(show)
cli.add_command(sync)
cli.add_command(drift)
cli.add_command(destroy)
cli.add_command(import_cmd, name="import")
cli.add_command(publish)
cli.add_command(validate_query, name="validate-query")
cli.add_command(init)
cli.add_command(discover)
cli.add_command(backup)
cli.add_command(auth)
cli.add_command(health)
cli.add_command(metrics)
cli.add_command(find)
cli.add_command(migrate)
