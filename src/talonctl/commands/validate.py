"""talonctl validate — validate all templates."""

import click

from talonctl.commands._common import (
    console,
    filter_options,
    state_options,
    parse_filters,
    init_orchestrator,
)
from talonctl.utils.auth import load_credentials


def _validate_v2_files(console) -> bool:
    """Validate any v2 envelope files under resources/. Returns True if any errors.

    Additive: only files whose first document declares apiVersion talon/v2 are
    handled here; v1 files are left to the existing validation path.
    """
    import yaml
    from talonctl.project import find_project_root
    from talonctl.core.envelope import API_VERSION
    from talonctl.core.envelope_loader import load_envelopes
    from talonctl.core.envelope_validation import (
        validate_authored_envelope,
        check_depends_on_cycles,
        check_whitespace_hygiene,
    )

    try:
        resources_dir = find_project_root() / "resources"
    except Exception:
        return False
    if not resources_dir.exists():
        return False

    all_envs = []
    had_errors = False
    for yaml_file in sorted(resources_dir.rglob("*.yaml")):
        try:
            first = next(iter(yaml.safe_load_all(yaml_file.read_text())), None)
        except yaml.YAMLError as e:
            console.print(f"[red]✗ {yaml_file}: YAML parse error: {e}[/red]")
            had_errors = True
            continue
        except Exception:
            # Non-YAML error (e.g. unreadable file) — skip defensively.
            continue
        if not (isinstance(first, dict) and first.get("apiVersion") == API_VERSION):
            continue  # leave v1 files to the existing path
        try:
            envs = load_envelopes(yaml_file)
        except ValueError as e:
            console.print(f"[red]✗ {yaml_file}: {e}[/red]")
            had_errors = True
            continue
        for env in envs:
            errs = validate_authored_envelope(env) + check_whitespace_hygiene(env)
            if errs:
                had_errors = True
                for msg in errs:
                    console.print(
                        f"[red]✗ {yaml_file} [{env.kind} {env.metadata.get('resource_id', '?')}]: {msg}[/red]"
                    )
        all_envs.extend(envs)

    for msg in check_depends_on_cycles(all_envs):
        console.print(f"[red]✗ {msg}[/red]")
        had_errors = True
    return had_errors


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

    if parse_queries:
        if load_credentials() is None:
            console.print("[red]✗ --queries requires configured credentials.[/red]")
            console.print("  Run 'talonctl auth setup' or unset --queries for schema-only validation.")
            raise SystemExit(1)

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
        has_errors = _validate_v2_files(console) or has_errors  # additive: v2 envelope validation
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
