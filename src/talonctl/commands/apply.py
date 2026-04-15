"""talonctl apply — execute planned changes."""

import click
from rich.prompt import Confirm

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
@click.option("--auto-approve", is_flag=True, help="Skip confirmation prompts")
@click.option("--parallel", type=int, default=10, help="Max parallel operations")
@click.option("--skip-query-validation", is_flag=True, help="Skip CQL query validation")
@click.option("--validation-workers", type=int, default=20, help="Parallel validation workers")
@click.pass_context
def apply(
    ctx,
    resources,
    tags,
    names,
    state_file,
    remote_state,
    remote_state_search_domain,
    remote_state_filename,
    auto_approve,
    parallel,
    skip_query_validation,
    validation_workers,
):
    """Execute planned changes."""
    console.print("[bold blue]Applying changes...[/bold blue]\n")
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
        from talonctl.core import PlanFormatter, ResourceAction

        plan_result = orchestrator.plan(**filters)
        formatter = PlanFormatter(console, verbose=verbose)
        formatter.format_plan(plan_result)

        if plan_result.query_validation_results:
            invalid = sum(1 for r in plan_result.query_validation_results if not r.is_valid)
            if invalid > 0:
                console.print("[red]✗ Apply blocked due to invalid queries[/red]\n")
                ctx.exit(1)
                return

        changes_to_apply = [c for c in plan_result.changes if c.action != ResourceAction.NO_CHANGE]
        if not changes_to_apply:
            console.print("[dim]No changes to apply.[/dim]\n")
            return

        if not auto_approve:
            if not Confirm.ask("\n[yellow]Do you want to apply these changes?[/yellow]"):
                console.print("[dim]Apply cancelled.[/dim]\n")
                return

        console.print("\n[bold blue]Deploying resources...[/bold blue]\n")
        result = orchestrator.apply(plan=plan_result, parallel=parallel, auto_approve=auto_approve)

        if result.success:
            console.print(
                f"\n[green]✓ Deployment successful![/green] "
                f"Deployed {len(result.deployed)} resources in {result.duration:.1f}s\n"
            )
        else:
            console.print(
                f"\n[red]✗ Deployment failed.[/red] "
                f"{len(result.deployed)} deployed, {len(result.failed)} failed, "
                f"{len(result.skipped)} skipped\n"
            )
            if result.failed:
                console.print("[bold red]Failed resources:[/bold red]")
                for resource_id, error in result.failed:
                    console.print(f"  • {resource_id}: {error}")
                console.print()
            ctx.exit(1)
    except Exception as e:
        console.print(f"[red]✗ Error during apply: {e}[/red]")
        if verbose:
            import traceback

            traceback.print_exc()
        ctx.exit(1)
