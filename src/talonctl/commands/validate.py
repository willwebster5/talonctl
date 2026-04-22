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
@click.option(
    "--queries",
    "-Q",
    "parse_queries",
    is_flag=True,
    help="After schema validation, CQL-parse every query against NGSIEM. Requires credentials.",
)
@click.pass_context
def validate(ctx, resources, tags, names, state_file, parse_queries):
    """Validate all templates without deploying."""
    console.print("[bold blue]Validating templates...[/bold blue]\n")
    verbose = ctx.obj.get("verbose", False)

    # Schema validation is always offline — no credentials needed.
    orchestrator = init_orchestrator(
        state_file=state_file,
        require_credentials=parse_queries,
    )
    filters = parse_filters(resources, tags, names)

    try:
        from talonctl.core import PlanFormatter

        results = orchestrator.validate(**filters)
        formatter = PlanFormatter(console, verbose=verbose)
        formatter.format_validation_results(results)

        has_errors = any(errors for errors in results.values() if errors)
        if has_errors:
            raise SystemExit(1)

        if parse_queries:
            try:
                query_results = orchestrator.validate_queries(**filters)
            except ValueError as e:
                console.print("[red]✗ --queries requires configured credentials.[/red]")
                console.print("  Run 'talonctl auth setup' or unset --queries for schema-only validation.")
                if verbose:
                    console.print(f"  [dim]{e}[/dim]")
                raise SystemExit(1)

            formatter.format_query_validation(query_results)
            if any(not r.is_valid for r in query_results):
                raise SystemExit(1)

    except SystemExit:
        raise
    except Exception as e:
        console.print(f"[red]✗ Error during validation: {e}[/red]")
        if verbose:
            import traceback

            traceback.print_exc()
        raise SystemExit(1)
