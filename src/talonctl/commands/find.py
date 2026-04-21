"""talonctl find — resolve any identifier to one or more resources."""

import json
import sys
from typing import Optional

import click
from rich.panel import Panel
from rich.table import Table

from talonctl.commands._common import console, get_state_file_path
from talonctl.core.resource_finder import FindOutput, ResourceFinder

_RESOURCE_TYPES = [
    "detection",
    "saved_search",
    "workflow",
    "lookup_file",
    "rtr_script",
    "rtr_put_file",
    "dashboard",
]


def _load_state(state_file: Optional[str]) -> Optional[dict]:
    """Return state dict, or None if no state file exists."""
    path = get_state_file_path(state_file)
    if not path.exists() or path.stat().st_size == 0:
        return None
    try:
        return json.loads(path.read_text())
    except json.JSONDecodeError as e:
        click.echo(f"Error: corrupt state file at {path}: {e}", err=True)
        sys.exit(2)


def _discover_templates():
    """Walk the resources/ tree; returns a list of DiscoveredTemplate or []."""
    try:
        from talonctl.core.template_discovery import TemplateDiscovery

        discovery = TemplateDiscovery()
        all_templates = discovery.discover_all()
        flat = []
        for templates in all_templates.values():
            flat.extend(templates)
        return flat
    except Exception as e:
        click.echo(f"Warning: failed to discover templates: {e}", err=True)
        return []


def _render_table(output: FindOutput) -> None:
    header = f"[bold]query:[/bold] {output.query}   [bold]strategy:[/bold] {output.strategy_used}   [bold]matches:[/bold] {len(output.matches)}"
    console.print(header)

    if output.strategy_used == "composite_id_non_iac" and output.non_iac_info:
        info = output.non_iac_info
        console.print(
            Panel(
                f"[bold]{info.label}[/bold]\nTune at: {info.tuning_location}\n\n{info.tip}",
                title=f"Non-IaC alert ({info.prefix})",
                border_style="yellow",
            )
        )
        return

    if not output.matches:
        console.print("[dim]No matches.[/dim]")
        return

    table = Table(show_header=True, header_style="bold cyan")
    table.add_column("TYPE", style="cyan")
    table.add_column("RESOURCE_ID", no_wrap=True)
    table.add_column("NAME")
    table.add_column("RULE_ID")
    table.add_column("STATUS")
    table.add_column("TEMPLATE")
    for m in output.matches:
        rid = (m.rule_id[:8] + "…") if m.rule_id else "—"
        table.add_row(
            m.resource_type,
            m.resource_id,
            m.display_name,
            rid,
            m.status or "—",
            m.template_path or "—",
        )
    console.print(table)


def _exit_code(output: FindOutput) -> int:
    if output.matches:
        return 0
    if output.non_iac_info is not None:
        return 0
    return 1


@click.command()
@click.argument("query")
@click.option(
    "--type",
    "resource_type",
    type=click.Choice(_RESOURCE_TYPES),
    default=None,
    help="Filter to a single resource type.",
)
@click.option(
    "--format",
    "output_format",
    type=click.Choice(["table", "json", "path"]),
    default="table",
    help="Output format.",
)
@click.option(
    "--include-undeployed",
    is_flag=True,
    default=False,
    help="Also search on-disk templates not yet in state.",
)
@click.option("--state-file", type=str, default=None, help="Custom state file path.")
def find(query, resource_type, output_format, include_undeployed, state_file):
    """Resolve any identifier to one or more talonctl-managed resources."""
    state = _load_state(state_file)
    if state is None:
        if include_undeployed:
            state = {"resources": {}}
        else:
            click.echo(
                "No state file; pass --include-undeployed to search templates.",
                err=True,
            )
            state = {"resources": {}}

    templates = _discover_templates() if include_undeployed else None
    finder = ResourceFinder(state, templates=templates)
    output = finder.find(query, resource_type=resource_type)

    _render_table(output)
    sys.exit(_exit_code(output))
