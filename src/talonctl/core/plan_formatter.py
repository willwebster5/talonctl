"""
Plan Formatter - Terraform-Style Output

Formats deployment plans in a clear, Terraform-like style with:
- Color-coded actions (+create, ~update, -delete, =no change)
- Detailed diffs for updates
- Deployment wave visualization
- Summary statistics
"""

import logging
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

# Import ResourceChange and ResourceAction from the canonical definition in base_provider
from .base_provider import ResourceChange, ResourceAction
from .deployment_orchestrator import QueryValidationResult

logger = logging.getLogger(__name__)


@dataclass
class DeploymentPlan:
    """Represents a complete deployment plan"""

    changes: List[ResourceChange]
    waves: List[List[str]]  # Deployment waves (lists of resource IDs)
    statistics: Dict[str, int]
    query_validation_results: Optional[List[QueryValidationResult]] = None


class PlanFormatter:
    """
    Formats deployment plans for terminal display

    Uses Rich library for beautiful, color-coded output similar to Terraform.
    """

    # Action symbols and colors
    ACTION_SYMBOLS = {"create": "+", "update": "~", "replace": "!", "delete": "-", "no-change": "="}

    ACTION_COLORS = {"create": "green", "update": "yellow", "replace": "magenta", "delete": "red", "no-change": "dim"}

    def __init__(self, console: Optional[Console] = None, verbose: bool = False):
        """
        Initialize formatter

        Args:
            console: Rich Console instance (creates new if not provided)
            verbose: Show full deployment order and detailed output
        """
        self.console = console or Console()
        self.verbose = verbose

    def _format_resource_label(self, resource_id: str, display_name: Optional[str] = None) -> str:
        """
        Format resource label showing both resource_id and display name

        Args:
            resource_id: Stable resource identifier (e.g., "saved_search.aws_service_accounts")
            display_name: Human-readable display name (e.g., "AWS Service Account Detector")

        Returns:
            Formatted label string
        """
        # Extract just the resource name from the full ID (e.g., "aws_service_accounts" from "saved_search.aws_service_accounts")
        resource_name = resource_id.split(".", 1)[1] if "." in resource_id else resource_id

        # If display_name is different from resource_name, show both
        if display_name and display_name != resource_name:
            return f"[bold]{resource_id}[/bold] [dim]({display_name})[/dim]"
        else:
            return f"[bold]{resource_id}[/bold]"

    def format_plan(self, plan: DeploymentPlan) -> None:
        """
        Format and display complete deployment plan

        Args:
            plan: Deployment plan to display
        """
        # Display query validation results first if present
        if plan.query_validation_results:
            self.format_query_validation(plan.query_validation_results)

        self.console.print()
        self.console.print(Panel.fit("[bold]Deployment Plan[/bold]", border_style="blue"))
        self.console.print()

        # Group changes by action
        creates = [c for c in plan.changes if c.action == ResourceAction.CREATE]
        updates = [c for c in plan.changes if c.action == ResourceAction.UPDATE]
        replaces = [c for c in plan.changes if c.action == ResourceAction.REPLACE]
        deletes = [c for c in plan.changes if c.action == ResourceAction.DELETE]
        no_changes = [c for c in plan.changes if c.action == ResourceAction.NO_CHANGE]

        # Display each group
        for change in creates:
            self._format_create(change)

        for change in updates:
            self._format_update(change)

        for change in replaces:
            self._format_replace(change)

        for change in deletes:
            self._format_delete(change)

        # Only show a few no-change resources
        if no_changes and len(no_changes) <= 5:
            for change in no_changes:
                self._format_no_change(change)
        elif no_changes:
            self.console.print(f"\n[dim]... and {len(no_changes)} resources with no changes[/dim]\n")

        # Display deployment waves
        if plan.waves:
            self._format_waves(plan.waves)

        # Display summary
        self._format_summary(plan.statistics)

    def _format_create(self, change: ResourceChange) -> None:
        """Format a resource creation"""
        symbol = self.ACTION_SYMBOLS[change.action.value]
        color = self.ACTION_COLORS[change.action.value]

        # Show resource_id and display name if different
        display_name = change.new_value.get("name") if change.new_value else None
        resource_label = self._format_resource_label(change.resource_id, display_name)

        self.console.print(f"[{color}]{symbol}[/{color}] {resource_label}")
        self.console.print(f"  [{color}]create[/{color}]")
        self.console.print()

        # Show key attributes
        if change.new_value:
            self._show_attributes(change.new_value, change.resource_type)

        self.console.print()

    def _format_update(self, change: ResourceChange) -> None:
        """Format a resource update with diff"""
        symbol = self.ACTION_SYMBOLS[change.action.value]
        color = self.ACTION_COLORS[change.action.value]

        # Show resource_id and display name if different
        display_name = change.new_value.get("name") if change.new_value else None
        resource_label = self._format_resource_label(change.resource_id, display_name)

        self.console.print(f"[{color}]{symbol}[/{color}] {resource_label}")
        self.console.print(f"  [{color}]update[/{color}]")
        self.console.print()

        # Show changes
        if change.changes:
            for key, diff in change.changes.items():
                old_val = diff.get("old")
                new_val = diff.get("new")

                self.console.print(f"  [dim]{key}:[/dim]")
                self.console.print(f"    [red]- {self._format_value(old_val)}[/red]")
                self.console.print(f"    [green]+ {self._format_value(new_val)}[/green]")

        self.console.print()

    def _format_replace(self, change: ResourceChange) -> None:
        """Format a resource replacement (delete + recreate due to immutable field change)"""
        symbol = self.ACTION_SYMBOLS[change.action.value]
        color = self.ACTION_COLORS[change.action.value]

        display_name = change.new_value.get("name") if change.new_value else None
        resource_label = self._format_resource_label(change.resource_id, display_name)

        self.console.print(f"[{color}]{symbol}[/{color}] {resource_label}")
        self.console.print(f"  [{color}]replace[/{color}] [dim](delete + recreate)[/dim]")

        # Show what changed
        if change.changes:
            for field, vals in change.changes.items():
                if isinstance(vals, dict) and "old" in vals and "new" in vals:
                    self.console.print(f"  [dim]{field}:[/dim] {vals['old']} → {vals['new']}")

        self.console.print()

    def _format_delete(self, change: ResourceChange) -> None:
        """Format a resource deletion"""
        symbol = self.ACTION_SYMBOLS[change.action.value]
        color = self.ACTION_COLORS[change.action.value]

        # Show resource_id and display name if different
        display_name = change.old_value.get("name") if change.old_value else None
        resource_label = self._format_resource_label(change.resource_id, display_name)

        self.console.print(f"[{color}]{symbol}[/{color}] {resource_label}")
        self.console.print(f"  [{color}]delete[/{color}]")
        self.console.print()

    def _format_no_change(self, change: ResourceChange) -> None:
        """Format a resource with no changes"""
        symbol = self.ACTION_SYMBOLS[change.action.value]
        color = self.ACTION_COLORS[change.action.value]

        # Show resource_id and display name if different
        display_name = change.new_value.get("name") if change.new_value else None
        resource_label = self._format_resource_label(change.resource_id, display_name)

        self.console.print(f"[{color}]{symbol} {resource_label}[/{color}]")

    def _show_attributes(self, data: Dict[str, Any], resource_type: str) -> None:
        """
        Show relevant attributes for a resource

        Args:
            data: Resource data
            resource_type: Type of resource
        """
        # Define important attributes per resource type
        important_attrs = {
            "detection": ["severity", "description", "enabled"],
            "workflow": ["enabled", "trigger"],
            "saved_search": ["repository", "query"],
            "lookup_file": ["format", "source", "_search_domain"],
        }

        attrs_to_show = important_attrs.get(resource_type, ["name", "description"])

        for attr in attrs_to_show:
            if attr in data:
                value = data[attr]
                # Special formatting for certain attributes
                if attr == "query" and isinstance(value, str):
                    # Show first 2 lines of query
                    lines = value.strip().split("\n")
                    preview = "\n    ".join(lines[:2])
                    if len(lines) > 2:
                        preview += "\n    ..."
                    self.console.print(f"  [dim]{attr}:[/dim]")
                    self.console.print(f"    {preview}")
                else:
                    self.console.print(f"  [dim]{attr}:[/dim] {self._format_value(value)}")

    def _format_value(self, value: Any) -> str:
        """
        Format a value for display

        Args:
            value: Value to format

        Returns:
            Formatted string
        """
        if isinstance(value, str):
            # Truncate long strings
            if len(value) > 100:
                return f"{value[:97]}..."
            return value
        elif isinstance(value, (list, dict)):
            # Show type and length
            if isinstance(value, list):
                return f"List[{len(value)} items]"
            else:
                return f"Dict[{len(value)} keys]"
        elif value is None:
            return "null"
        else:
            return str(value)

    def _format_waves(self, waves: List[List[str]]) -> None:
        """
        Format deployment waves

        In default mode, shows a compact summary (wave count + total resources).
        In verbose mode, shows the full wave-by-wave resource listing.

        Args:
            waves: List of waves (each wave is list of resource IDs)
        """
        total_resources = sum(len(wave) for wave in waves)

        if not self.verbose:
            self.console.print(
                f"[bold]Deployment Order:[/bold] [dim]{total_resources} resources across {len(waves)} wave(s)[/dim]"
            )
            self.console.print()
            return

        self.console.print("[bold]Deployment Order:[/bold]")
        self.console.print()

        for idx, wave in enumerate(waves, 1):
            wave_type = "parallel" if len(wave) > 1 else "sequential"
            self.console.print(f"  [bold blue]Wave {idx}[/bold blue] ({wave_type}):")

            for resource_id in wave:
                self.console.print(f"    • {resource_id}")

        self.console.print()

    def _format_summary(self, statistics: Dict[str, int]) -> None:
        """
        Format summary statistics

        Args:
            statistics: Statistics dictionary
        """
        creates = statistics.get("create", 0)
        updates = statistics.get("update", 0)
        replaces = statistics.get("replace", 0)
        deletes = statistics.get("delete", 0)
        no_changes = statistics.get("no-change", 0)

        total_changes = creates + updates + replaces + deletes

        summary_parts = []
        if creates > 0:
            summary_parts.append(f"[green]{creates} to create[/green]")
        if updates > 0:
            summary_parts.append(f"[yellow]{updates} to update[/yellow]")
        if replaces > 0:
            summary_parts.append(f"[magenta]{replaces} to replace[/magenta]")
        if deletes > 0:
            summary_parts.append(f"[red]{deletes} to delete[/red]")
        if no_changes > 0:
            summary_parts.append(f"[dim]{no_changes} unchanged[/dim]")

        summary = ", ".join(summary_parts) if summary_parts else "[dim]No changes[/dim]"

        self.console.print(Panel.fit(f"[bold]Plan Summary:[/bold] {summary}", border_style="blue"))
        self.console.print()

        # Show warning if there are changes
        if total_changes > 0:
            self.console.print(
                f"[yellow]⚠[/yellow]  This plan will make [bold]{total_changes}[/bold] changes to your CrowdStrike environment."
            )
            self.console.print()

    def format_validation_results(self, results: Dict[str, List[str]]) -> None:
        """
        Format template validation results

        Args:
            results: Dictionary mapping resource ID to list of errors
        """
        total_templates = len(results)
        invalid_templates = sum(1 for errors in results.values() if errors)

        self.console.print()
        self.console.print(Panel.fit("[bold]Template Validation Results[/bold]", border_style="blue"))
        self.console.print()

        # Show errors (always shown)
        for resource_id, errors in results.items():
            if errors:
                self.console.print(f"[red]✗[/red] [bold]{resource_id}[/bold]")
                for error in errors:
                    self.console.print(f"    • {error}")
                self.console.print()

        # Show valid templates only in verbose mode
        if self.verbose:
            for resource_id, errors in results.items():
                if not errors:
                    self.console.print(f"[green]✓[/green] {resource_id}")

        # Summary
        if invalid_templates == 0:
            self.console.print(f"\n[green]✓ All {total_templates} templates are valid[/green]\n")
        else:
            self.console.print(f"\n[red]✗ {invalid_templates} of {total_templates} templates have errors[/red]\n")

    def format_query_validation(self, results: List[QueryValidationResult]) -> None:
        """Format CQL query validation results.

        Args:
            results: List of query validation results
        """
        if not results:
            return

        total = len(results)
        invalid = sum(1 for r in results if not r.is_valid)
        valid = total - invalid

        self.console.print()
        self.console.print(Panel.fit("[bold]Query Validation[/bold]", border_style="blue"))
        self.console.print()

        # Show invalid queries first
        for result in results:
            if not result.is_valid:
                self.console.print(f"[red]✗[/red] [bold]{result.resource_id}[/bold]")
                if result.location:
                    self.console.print(f"    [dim]at:[/dim] {result.location}")
                if result.error_message:
                    self.console.print(f"    [red]Error:[/red] {result.error_message}")
                if result.query_snippet:
                    self.console.print(f"    [dim]Query:[/dim] {result.query_snippet}")
                self.console.print()

        # Show valid queries (only if there are some invalid ones)
        if invalid > 0 and valid > 0:
            self.console.print(f"[green]✓[/green] {valid} queries valid\n")

        # Summary
        if invalid == 0:
            self.console.print(f"[green]✓ All {total} queries are valid[/green]\n")
        else:
            self.console.print(f"[red]✗ {invalid} of {total} queries rejected by LogScale[/red]\n")
            self.console.print("[yellow]⚠[/yellow]  Fix the above queries before running plan or apply.\n")

    def format_drift_report(self, report: Any) -> None:
        """
        Format drift detection results from a DriftReport.

        Renders categorized findings with color-coded symbols:
        - ~ yellow: Config drift (remote differs from template)
        - - red: Missing (in state/template but deleted remotely)
        - ? cyan: Orphaned (deployed but no IaC template)
        - ! magenta: Stale state (in state, no template, no remote)

        Args:
            report: DriftReport instance
        """
        self.console.print()
        self.console.print(Panel.fit("[bold]Drift Detection Results[/bold]", border_style="blue"))
        self.console.print()

        if not report.has_drift:
            self.console.print(f"[green]✓ No drift detected. {report.in_sync_count} resource(s) in sync.[/green]\n")
            if report.skipped_types:
                self.console.print(f"[dim]Skipped (no bulk fetch): {', '.join(report.skipped_types)}[/dim]\n")
            return

        # Config drift section
        if report.config_drift:
            self.console.print(
                f"[bold yellow]Config Drift[/bold yellow] "
                f"[dim]({len(report.config_drift)} resource(s) modified outside IaC)[/dim]\n"
            )
            for item in report.config_drift:
                self.console.print(f"  [yellow]~[/yellow] [bold]{item.resource_type}.{item.resource_id}[/bold]")
                if item.display_name != item.resource_id:
                    self.console.print(f"    [dim]name: {item.display_name}[/dim]")

                if item.field_diffs:
                    for field_name, diff in item.field_diffs.items():
                        # Check for sub-field diffs (e.g., search sub-fields)
                        sub_diffs = diff.get("_sub_diffs") if isinstance(diff, dict) else None
                        if sub_diffs:
                            for sub_name, sub_diff in sub_diffs.items():
                                self.console.print(f"    [dim]{field_name}.{sub_name}:[/dim]")
                                self.console.print(
                                    f"      [green]template:[/green] {self._format_value(sub_diff.get('template'))}"
                                )
                                self.console.print(
                                    f"      [red]remote:  [/red] {self._format_value(sub_diff.get('remote'))}"
                                )
                        else:
                            self.console.print(f"    [dim]{field_name}:[/dim]")
                            self.console.print(
                                f"      [green]template:[/green] {self._format_value(diff.get('template'))}"
                            )
                            self.console.print(f"      [red]remote:  [/red] {self._format_value(diff.get('remote'))}")
                else:
                    self.console.print("    [dim]hash mismatch (field-level diff unavailable)[/dim]")

                self.console.print()

        # Missing section
        if report.missing:
            self.console.print(
                f"[bold red]Missing[/bold red] "
                f"[dim]({len(report.missing)} resource(s) deleted from CrowdStrike)[/dim]\n"
            )
            for item in report.missing:
                display = item.display_name if item.display_name != item.resource_id else ""
                suffix = f" [dim]({display})[/dim]" if display else ""
                self.console.print(f"  [red]-[/red] [bold]{item.resource_type}.{item.resource_id}[/bold]{suffix}")
            self.console.print()

        # Orphaned section
        if report.orphaned:
            self.console.print(
                f"[bold cyan]Orphaned[/bold cyan] "
                f"[dim]({len(report.orphaned)} resource(s) deployed but no IaC template)[/dim]\n"
            )
            for item in report.orphaned:
                self.console.print(f"  [cyan]?[/cyan] [bold]{item.resource_type}.{item.resource_id}[/bold]")
            self.console.print()

        # Stale state section
        if report.stale_state:
            self.console.print(
                f"[bold magenta]Stale State[/bold magenta] "
                f"[dim]({len(report.stale_state)} state entries with no template or remote resource)[/dim]\n"
            )
            for item in report.stale_state:
                display = item.display_name if item.display_name != item.resource_id else ""
                suffix = f" [dim]({display})[/dim]" if display else ""
                self.console.print(
                    f"  [magenta]![/magenta] [bold]{item.resource_type}.{item.resource_id}[/bold]{suffix}"
                )
            self.console.print()

        # Skipped types
        if report.skipped_types:
            self.console.print(f"[dim]Skipped (no bulk fetch): {', '.join(report.skipped_types)}[/dim]\n")

        # Errors
        if report.errors:
            self.console.print("[bold red]Errors:[/bold red]")
            for error in report.errors:
                self.console.print(f"  [red]✗[/red] {error}")
            self.console.print()

        # Summary panel
        summary_lines = []
        summary_lines.append(f"[yellow]~[/yellow] Config drift:  {len(report.config_drift)}")
        summary_lines.append(f"[red]-[/red] Missing:       {len(report.missing)}")
        summary_lines.append(f"[cyan]?[/cyan] Orphaned:      {len(report.orphaned)}")
        summary_lines.append(f"[magenta]![/magenta] Stale state:   {len(report.stale_state)}")
        summary_lines.append(f"[green]=[/green] In sync:       {report.in_sync_count}")

        self.console.print(Panel.fit("\n".join(summary_lines), title="[bold]Summary[/bold]", border_style="blue"))
        self.console.print()

        # Actionable tips
        if report.config_drift:
            self.console.print("[dim]Tip: Run [bold]apply[/bold] to push template state to CrowdStrike[/dim]")
        if report.missing:
            self.console.print(
                "[dim]Tip: Run [bold]apply[/bold] to recreate missing resources, "
                "or [bold]sync[/bold] to clean up stale state[/dim]"
            )
        if report.stale_state:
            self.console.print("[dim]Tip: Run [bold]sync[/bold] to remove stale state entries[/dim]")
        if report.config_drift or report.missing or report.stale_state:
            self.console.print()

    # Keep old method name as alias for backward compatibility
    def format_drift_results(self, drift: Dict[str, Any]) -> None:
        """Legacy drift format - delegates to format_drift_report if given a DriftReport."""
        if hasattr(drift, "has_drift"):
            self.format_drift_report(drift)
        else:
            # Fallback for old-style dict format
            self.console.print("[yellow]Legacy drift format detected[/yellow]\n")

    def format_state_view(self, state: Dict[str, List[Dict[str, Any]]]) -> None:
        """
        Format state view as a table

        Args:
            state: State dictionary grouped by resource type
        """
        for resource_type, resources in state.items():
            if not resources:
                continue

            table = Table(title=f"{resource_type.title()} Resources")
            table.add_column("Name", style="cyan")
            table.add_column("ID", style="dim")
            table.add_column("Status", style="green")
            table.add_column("Last Modified", style="yellow")

            for resource in resources:
                table.add_row(
                    resource.get("name", "N/A"),
                    resource.get("id", "N/A"),
                    resource.get("status", "deployed"),
                    resource.get("last_modified", "N/A")[:19],  # Trim timestamp
                )

            self.console.print(table)
            self.console.print()
