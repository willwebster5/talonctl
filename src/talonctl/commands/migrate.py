"""talonctl migrate — rewrap v1 templates to v2 and reconcile state to v4.

Dry-run by default. `--write` is the only flag that mutates disk. Idempotent.
Orphans/unmanaged/conflicts are reported, never deleted or created.
"""

from __future__ import annotations

import json
from pathlib import Path

import click
from rich.table import Table

from talonctl.commands._common import (
    console,
    get_resources_dir,
    get_state_file_path,
    resolve_resources_dir,
    state_options,
)
from talonctl.core.migrate import (
    MigrationReport,
    build_template_index,
    reconcile_state,
    scan_templates,
)
from talonctl.core.state_manager import StateManager
from talonctl.core.template_discovery import TemplateDiscovery


@click.command()
@state_options
@click.option("--write", is_flag=True, help="Apply changes (default: dry-run, writes nothing).")
@click.option("--templates-only", is_flag=True, help="Only rewrap templates; skip state reconciliation.")
@click.option("--state-only", is_flag=True, help="Only reconcile state; skip template rewrap.")
@click.option("--format", "fmt", type=click.Choice(["text", "json"]), default="text")
@click.option("--output", "-o", type=click.Path(), help="Write JSON report to file.")
def migrate(state_file, write, templates_only, state_only, fmt, output):
    """Migrate v1 templates -> v2 and v3 state -> v4 (dry-run by default)."""
    if templates_only and state_only:
        raise click.UsageError("--templates-only and --state-only are mutually exclusive.")

    do_templates = not state_only
    do_state = not templates_only

    report = MigrationReport(dry_run=not write)

    if do_templates:
        resources_dir = get_resources_dir()
        report.rewraps = scan_templates(resources_dir)
        if write:
            for fr in report.rewraps:
                if fr.status == "rewrap" and fr.new_text is not None:
                    fr.path.write_text(fr.new_text)

    if do_state:
        state_path = get_state_file_path(state_file)
        sm = StateManager(state_file_path=state_path) if state_path.exists() else None
        resources = sm.export_to_dict().get("resources", {}) if sm else {}
        index = build_template_index(TemplateDiscovery(resolve_resources_dir()).discover_all())
        report.state = reconcile_state(resources, index)
        if write and sm is not None and report.state.rekeyed:
            for rtype, old, new in report.state.rekeyed:
                rs = sm.get_resource(rtype, old)
                if rs is not None:
                    sm.set_resource(rtype, new, rs)
                    sm.delete_resource(rtype, old)
            sm.save()

    if fmt == "json" or output:
        data = json.dumps(report.to_dict(), indent=2)
        if output:
            Path(output).write_text(data)
            console.print(f"[green]Report written to {output}[/green]")
        else:
            console.print_json(data)
    else:
        _render_text(report)


def _render_text(report: MigrationReport) -> None:
    mode = "DRY-RUN (no changes written — pass --write to apply)" if report.dry_run else "WRITE"
    console.print(f"[bold blue]talonctl migrate[/bold blue]  [dim]{mode}[/dim]\n")

    if report.rewraps:
        t = Table(title="Templates")
        t.add_column("status")
        t.add_column("file")
        t.add_column("details")
        for fr in report.rewraps:
            detail = ""
            if fr.status == "rewrap":
                detail = f"{', '.join(fr.kinds)} · {fr.comments_dropped} comment(s) dropped"
            elif fr.status == "error":
                detail = "; ".join(fr.errors)
            t.add_row(fr.status, str(fr.path), detail)
        console.print(t)
        if any(fr.status == "rewrap" and fr.comments_dropped for fr in report.rewraps):
            console.print("[yellow]Comments dropped — originals preserved in git history.[/yellow]")

    s = report.state
    if s.rekeyed or s.orphans or s.unmanaged or s.conflicts:
        t = Table(title="State")
        t.add_column("category")
        t.add_column("detail")
        for rtype, old, new in s.rekeyed:
            t.add_row("rekey", f"{rtype}: {old} -> {new}")
        for rtype, key in s.orphans:
            t.add_row("orphan", f"{rtype}.{key} (state has no template)")
        for rtype, rid in s.unmanaged:
            t.add_row("unmanaged", f"{rtype}.{rid} (template has no state)")
        for rtype, key, target, reason in s.conflicts:
            t.add_row("conflict", f"{rtype}.{key} -> {target}: {reason}")
        console.print(t)
        if s.orphans or s.unmanaged or s.conflicts:
            console.print("[dim]Orphans/unmanaged/conflicts are reported only — never deleted or created.[/dim]")

    actionable_templates = any(fr.status in ("rewrap", "error") for fr in report.rewraps)
    actionable_state = bool(s.rekeyed or s.orphans or s.unmanaged or s.conflicts)
    if not actionable_templates and not actionable_state:
        console.print("[green]Nothing to migrate — templates are v2 and state is reconciled.[/green]")
