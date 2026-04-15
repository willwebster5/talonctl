"""talonctl validate — validate all templates."""

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
def validate(ctx, resources, tags, names, state_file):
    """Validate all templates without deploying."""
    console.print("[bold blue]Validating templates...[/bold blue]\n")
    verbose = ctx.obj.get("verbose", False)

    orchestrator = init_orchestrator(state_file=state_file, require_credentials=False)
    filters = parse_filters(resources, tags, names)

    try:
        from talonctl.core import PlanFormatter

        results = orchestrator.validate(**filters)
        formatter = PlanFormatter(console, verbose=verbose)
        formatter.format_validation_results(results)
        has_errors = any(errors for errors in results.values() if errors)
        if has_errors:
            raise SystemExit(1)
    except SystemExit:
        raise
    except Exception as e:
        console.print(f"[red]✗ Error during validation: {e}[/red]")
        if verbose:
            import traceback

            traceback.print_exc()
        raise SystemExit(1)
