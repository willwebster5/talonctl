"""talonctl drift — detect manual changes in CrowdStrike."""

import click

from talonctl.commands._common import (
    console, filter_options, state_options, parse_filters, init_orchestrator,
)


@click.command()
@filter_options
@state_options
@click.pass_context
def drift(ctx, resources, tags, names, state_file):
    """Detect manual changes in CrowdStrike."""
    console.print("[bold blue]Detecting drift...[/bold blue]\n")
    console.print("[cyan]Comparing templates, state, and remote CrowdStrike resources...[/cyan]\n")
    verbose = ctx.obj.get('verbose', False)

    orchestrator = init_orchestrator(state_file=state_file)
    filters = parse_filters(resources, tags, names)

    try:
        from talonctl.core import PlanFormatter
        report = orchestrator.drift(**filters)

        formatter = PlanFormatter(console, verbose=verbose)
        formatter.format_drift_report(report)

        # Exit code 1 if drift detected (useful for CI)
        ctx.exit(1 if report.has_drift else 0)

    except Exception as e:
        console.print(f"[red]✗ Error during drift detection: {e}[/red]")
        if verbose:
            import traceback
            traceback.print_exc()
        ctx.exit(1)
