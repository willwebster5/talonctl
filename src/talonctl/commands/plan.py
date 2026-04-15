"""talonctl plan — show what changes would be made."""

import click

from talonctl.commands._common import (
    console,
    filter_options,
    state_options,
    remote_state_options,
    parse_filters,
    init_orchestrator,
)


@click.command()
@filter_options
@state_options
@remote_state_options
@click.option("--skip-query-validation", is_flag=True, help="Skip CQL query validation")
@click.option("--validation-workers", type=int, default=20, help="Parallel validation workers")
@click.pass_context
def plan(
    ctx,
    resources,
    tags,
    names,
    state_file,
    remote_state,
    remote_state_search_domain,
    remote_state_filename,
    skip_query_validation,
    validation_workers,
):
    """Show what changes would be made."""
    console.print("[bold blue]Generating deployment plan...[/bold blue]\n")
    verbose = ctx.obj.get("verbose", False)

    orchestrator = init_orchestrator(
        state_file=state_file,
        remote_state=remote_state,
        remote_state_search_domain=remote_state_search_domain,
        remote_state_filename=remote_state_filename,
    )
    filters = parse_filters(resources, tags, names)
    filters["skip_query_validation"] = skip_query_validation
    filters["validation_workers"] = validation_workers

    try:
        from talonctl.core import PlanFormatter

        result = orchestrator.plan(**filters)
        formatter = PlanFormatter(console, verbose=verbose)
        formatter.format_plan(result)

        if result.query_validation_results:
            invalid = sum(1 for r in result.query_validation_results if not r.is_valid)
            if invalid > 0:
                console.print("[red]✗ Plan blocked due to invalid queries[/red]\n")
                ctx.exit(1)
    except Exception as e:
        console.print(f"[red]✗ Error generating plan: {e}[/red]")
        if verbose:
            import traceback

            traceback.print_exc()
        ctx.exit(1)
