"""talonctl init — scaffold a new talonctl project."""

import json
import shutil
from pathlib import Path

import click

from talonctl.commands._common import console
from talonctl.core.state_manager import StateManager

RESOURCE_DIRS = [
    "detections",
    "saved_searches",
    "dashboards",
    "lookup_files",
    "rtr_scripts",
    "rtr_put_files",
]


@click.command()
@click.argument("path", required=False, type=click.Path())
@click.pass_context
def init(ctx, path):
    """Scaffold a new talonctl project."""
    project_dir = Path(path) if path else Path.cwd()
    project_dir = project_dir.resolve()

    # Refuse if already initialized
    if (project_dir / ".crowdstrike").exists():
        console.print("[red]✗ Directory already contains a talonctl project (.crowdstrike/ exists)[/red]")
        raise SystemExit(1)
        return

    project_dir.mkdir(parents=True, exist_ok=True)

    # Create resource directories
    for resource_type in RESOURCE_DIRS:
        (project_dir / "resources" / resource_type).mkdir(parents=True, exist_ok=True)

    # Create knowledge directories
    for subdir in ["context", "patterns", "techniques", "tuning", "metrics", "hunts", "ideas"]:
        (project_dir / "knowledge" / subdir).mkdir(parents=True, exist_ok=True)

    # Copy template files from bundled templates
    templates_dir = Path(__file__).parent.parent / "templates" / "init"
    _copy_templates(templates_dir, project_dir)

    # Create state file. Use the same `version` key/value StateManager reads/writes
    # (sourced from STATE_VERSION) so a freshly-scaffolded project is never stamped
    # with a stale or mismatched format version.
    (project_dir / ".crowdstrike").mkdir(exist_ok=True)
    state = {"version": StateManager.STATE_VERSION, "resources": {}}
    (project_dir / ".crowdstrike" / "deployed_state.json").write_text(json.dumps(state, indent=2) + "\n")

    # Create .gitignore
    gitignore_template = templates_dir / "gitignore"
    if gitignore_template.exists():
        shutil.copy2(gitignore_template, project_dir / ".gitignore")

    console.print(f"[green]✓ Initialized talonctl project at {project_dir}[/green]\n")
    console.print("Next steps:")
    console.print("  1. Edit knowledge/context/environmental-context.md with your environment details")
    console.print("  2. Add detection templates to resources/detections/")
    console.print("  3. Run [bold]talonctl validate[/bold] to check your templates")
    console.print("  4. Run [bold]talonctl plan[/bold] to preview changes\n")


def _copy_templates(templates_dir: Path, project_dir: Path):
    """Copy template files from bundled templates to project directory."""
    if not templates_dir.exists():
        return
    for template_file in templates_dir.rglob("*"):
        if template_file.is_file() and template_file.name != "gitignore" and template_file.name != "state.json":
            relative = template_file.relative_to(templates_dir)
            target = project_dir / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(template_file, target)
