#!/usr/bin/env python3
"""
CrowdStrike Unified Resource Deployment CLI

Terraform-like CLI for managing all CrowdStrike NGSIEM resources:
- Detections
- Workflows
- Saved Searches
- Lookup Files
- RTR Scripts
- RTR Put Files

Commands:
  plan       Show what changes would be made
  apply      Execute planned changes
  destroy    Remove specified resources
  show       Display current state
  sync       Synchronize state with CrowdStrike
  drift      Detect manual changes in CrowdStrike
  validate   Validate all templates without deploying
  import     Import existing resources to state
  publish    Activate inactive detection rules for production

Examples:
  # Plan all resources
  resource_deploy.py plan

  # Apply with auto-approval (CI/CD)
  resource_deploy.py apply --auto-approve

  # Plan only detections and saved searches
  resource_deploy.py plan --resources=detection,saved_search

  # Validate all templates
  resource_deploy.py validate

  # Publish inactive detection rules
  resource_deploy.py publish --auto-approve
"""

# Standard setup for all scripts
import sys
from pathlib import Path

def find_scripts_dir():
    """Find scripts directory from any subdirectory"""
    current = Path(__file__).resolve().parent
    while current.name != 'scripts' and current != current.parent:
        current = current.parent
    return current if current.name == 'scripts' else Path(__file__).parent

SCRIPTS_DIR = find_scripts_dir()
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

from common import PATHS, load_auth, setup_imports
setup_imports()

# Now regular imports work
import os
import argparse
import logging
from datetime import datetime
from typing import Optional, List

from rich.console import Console
from rich.prompt import Confirm
from rich import print as rprint

try:
    from falconpy import APIHarnessV2
    from utils.auth import load_credentials
    from core import (
        DeploymentOrchestrator,
        PlanFormatter
    )
except ImportError as e:
    print(f"Error importing required modules: {e}")
    print("Please ensure FalconPy is installed and utils/auth.py exists.")
    sys.exit(1)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Rich console for pretty output
# Check for NO_COLOR environment variable (standard convention)
disable_color = os.getenv('NO_COLOR') is not None or os.getenv('CI') is not None
console = Console(
    width=200 if os.getenv('CI') else None,
    force_terminal=not disable_color,  # Don't force terminal if colors disabled
    no_color=disable_color,
    force_jupyter=False
)


def parse_args():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(
        description='CrowdStrike Unified Resource Deployment CLI',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s plan
  %(prog)s apply --auto-approve
  %(prog)s plan --resources=detection,saved_search
  %(prog)s validate
  %(prog)s show --resources=workflow
  %(prog)s drift
        """
    )

    # Subcommands
    subparsers = parser.add_subparsers(dest='command', help='Command to execute')

    # plan command
    plan_parser = subparsers.add_parser('plan', help='Show what changes would be made')
    add_filter_args(plan_parser)
    add_remote_state_args(plan_parser)
    plan_parser.add_argument(
        '--skip-query-validation',
        action='store_true',
        help='Skip FQL query validation for detections'
    )
    plan_parser.add_argument(
        '--validation-workers',
        type=int,
        default=20,
        help='Number of parallel workers for query validation (default: 20)'
    )

    # apply command
    apply_parser = subparsers.add_parser('apply', help='Execute planned changes')
    add_filter_args(apply_parser)
    add_remote_state_args(apply_parser)
    apply_parser.add_argument(
        '--auto-approve',
        action='store_true',
        help='Skip confirmation prompts'
    )
    apply_parser.add_argument(
        '--parallel',
        type=int,
        default=10,
        help='Maximum parallel operations (default: 10)'
    )
    apply_parser.add_argument(
        '--skip-query-validation',
        action='store_true',
        help='Skip FQL query validation for detections'
    )
    apply_parser.add_argument(
        '--validation-workers',
        type=int,
        default=20,
        help='Number of parallel workers for query validation (default: 20)'
    )

    # destroy command
    destroy_parser = subparsers.add_parser('destroy', help='Remove specified resources')
    add_filter_args(destroy_parser)
    destroy_parser.add_argument(
        '--auto-approve',
        action='store_true',
        help='Skip confirmation prompts'
    )

    # show command
    show_parser = subparsers.add_parser('show', help='Display current state')
    add_filter_args(show_parser)
    show_parser.add_argument(
        '--format',
        choices=['table', 'json'],
        default='table',
        help='Output format'
    )

    # sync command
    sync_parser = subparsers.add_parser('sync', help='Synchronize state with CrowdStrike')
    add_filter_args(sync_parser)

    # drift command
    drift_parser = subparsers.add_parser('drift', help='Detect manual changes in CrowdStrike')
    add_filter_args(drift_parser)

    # validate command
    validate_parser = subparsers.add_parser('validate', help='Validate all templates')
    add_filter_args(validate_parser)

    # import command
    import_parser = subparsers.add_parser('import', help='Import existing CrowdStrike resources as YAML templates')
    add_filter_args(import_parser)
    import_parser.add_argument(
        '--plan',
        action='store_true',
        dest='import_plan',
        help='Dry-run: show what would be imported without writing files'
    )

    # publish command
    publish_parser = subparsers.add_parser('publish', help='Activate inactive detection rules for production')
    add_filter_args(publish_parser)
    publish_parser.add_argument(
        '--auto-approve',
        action='store_true',
        help='Skip confirmation prompts'
    )

    # validate-query command
    validate_query_parser = subparsers.add_parser(
        'validate-query',
        help='Validate a single LogScale/NGSIEM query'
    )
    validate_query_parser.add_argument(
        '--query', '-q',
        type=str,
        help='Query string to validate (use quotes)'
    )
    validate_query_parser.add_argument(
        '--file', '-f',
        type=str,
        help='Path to file containing query'
    )
    validate_query_parser.add_argument(
        '--template', '-t',
        type=str,
        help='Path to YAML template (extracts search.filter, search.query, or queryString for saved searches)'
    )

    # Global options
    parser.add_argument(
        '--state-file',
        type=str,
        help='Custom state file location'
    )

    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Enable verbose output'
    )

    return parser.parse_args()


def add_filter_args(parser):
    """Add common filter arguments to a parser"""
    parser.add_argument(
        '--resources',
        type=str,
        help='Filter by resource types (comma-separated): detection,workflow,saved_search,lookup_file,rtr_script,rtr_put_file'
    )
    parser.add_argument(
        '--tags',
        type=str,
        help='Filter by tags (comma-separated): aws,authentication'
    )
    parser.add_argument(
        '--names',
        type=str,
        help='Filter by resource names (glob patterns, comma-separated): aws_*,*_login'
    )


def add_remote_state_args(parser):
    """Add remote state arguments to a parser"""
    parser.add_argument(
        '--remote-state',
        action='store_true',
        help='Enable remote state sync to NGSIEM lookup files'
    )
    parser.add_argument(
        '--remote-state-search-domain',
        type=str,
        default='falcon',
        choices=['falcon', 'all', 'third-party', 'dashboards', 'parsers-repository'],
        help='NGSIEM search domain for remote state (default: falcon)'
    )
    parser.add_argument(
        '--remote-state-filename',
        type=str,
        default='unified_deployment_state.json',
        help='Filename for remote state (default: unified_deployment_state.json)'
    )


def parse_filters(args) -> dict:
    """Parse filter arguments into lists"""
    filters = {}

    if hasattr(args, 'resources') and args.resources:
        filters['resource_types'] = [r.strip() for r in args.resources.split(',')]

    if hasattr(args, 'tags') and args.tags:
        filters['tags'] = [t.strip() for t in args.tags.split(',')]

    if hasattr(args, 'names') and args.names:
        filters['names'] = [n.strip() for n in args.names.split(',')]

    return filters


def get_state_file_path(args) -> Path:
    """Determine state file path based on args."""
    if args.state_file:
        return Path(args.state_file)
    return PATHS.CROWDSTRIKE_DIR / 'deployed_state.json'


def init_orchestrator(args, require_credentials=True) -> DeploymentOrchestrator:
    """Initialize deployment orchestrator"""
    # Determine state file path (environment-aware)
    state_file_path = get_state_file_path(args)

    # Load CrowdStrike credentials if required
    creds = None
    if require_credentials:
        creds = load_credentials()
        falcon = APIHarnessV2(
            client_id=creds['falcon_client_id'],
            client_secret=creds['falcon_client_secret'],
            base_url=creds.get('base_url', 'US1')
        )
    else:
        # For commands that don't need API access (e.g., validate)
        falcon = None

    # Remote state configuration
    remote_state_enabled = getattr(args, 'remote_state', False)
    remote_state_search_domain = getattr(args, 'remote_state_search_domain', 'falcon')
    remote_state_filename = getattr(args, 'remote_state_filename', 'unified_deployment_state.json')

    # Create orchestrator (pass credentials for RTR providers)
    orchestrator = DeploymentOrchestrator(
        falcon_client=falcon,
        state_file_path=state_file_path,
        remote_state_enabled=remote_state_enabled,
        remote_state_search_domain=remote_state_search_domain,
        remote_state_filename=remote_state_filename,
        credentials=creds
    )

    return orchestrator


def command_plan(args):
    """Execute plan command"""
    console.print("[bold blue]Generating deployment plan...[/bold blue]\n")

    orchestrator = init_orchestrator(args)
    filters = parse_filters(args)

    try:
        # Add query validation parameters if present
        if hasattr(args, 'skip_query_validation'):
            filters['skip_query_validation'] = args.skip_query_validation
        if hasattr(args, 'validation_workers'):
            filters['validation_workers'] = args.validation_workers

        plan = orchestrator.plan(**filters)

        # Format and display plan
        formatter = PlanFormatter(console, verbose=args.verbose)
        formatter.format_plan(plan)

        # Check if any queries failed validation
        if plan.query_validation_results:
            invalid = sum(1 for r in plan.query_validation_results if not r.is_valid)
            if invalid > 0:
                console.print("[red]✗ Plan blocked due to invalid queries[/red]\n")
                return 1

        return 0

    except Exception as e:
        console.print(f"[red]✗ Error generating plan: {e}[/red]")
        if args.verbose:
            import traceback
            traceback.print_exc()
        return 1


def command_apply(args):
    """Execute apply command"""
    console.print("[bold blue]Applying changes...[/bold blue]\n")

    orchestrator = init_orchestrator(args)
    filters = parse_filters(args)

    try:
        # Add query validation parameters if present
        if hasattr(args, 'skip_query_validation'):
            filters['skip_query_validation'] = args.skip_query_validation
        if hasattr(args, 'validation_workers'):
            filters['validation_workers'] = args.validation_workers

        # Generate plan first
        plan = orchestrator.plan(**filters)

        # Show plan
        formatter = PlanFormatter(console, verbose=args.verbose)
        formatter.format_plan(plan)

        # Check if any queries failed validation
        if plan.query_validation_results:
            invalid = sum(1 for r in plan.query_validation_results if not r.is_valid)
            if invalid > 0:
                console.print("[red]✗ Apply blocked due to invalid queries[/red]\n")
                return 1

        # Count changes
        from core import ResourceAction
        changes_to_apply = [c for c in plan.changes if c.action != ResourceAction.NO_CHANGE]

        if not changes_to_apply:
            console.print("[dim]No changes to apply.[/dim]\n")
            return 0

        # Confirm unless auto-approve
        if not args.auto_approve:
            if not Confirm.ask("\n[yellow]Do you want to apply these changes?[/yellow]"):
                console.print("[dim]Apply cancelled.[/dim]\n")
                return 0

        # Execute deployment
        console.print("\n[bold blue]Deploying resources...[/bold blue]\n")

        result = orchestrator.apply(
            plan=plan,
            parallel=args.parallel,
            auto_approve=args.auto_approve
        )

        # Show results
        if result.success:
            console.print(
                f"\n[green]✓ Deployment successful![/green] "
                f"Deployed {len(result.deployed)} resources in {result.duration:.1f}s\n"
            )
            return 0
        else:
            console.print(
                f"\n[red]✗ Deployment failed.[/red] "
                f"{len(result.deployed)} deployed, {len(result.failed)} failed, "
                f"{len(result.skipped)} skipped\n"
            )

            # Show failures
            if result.failed:
                console.print("[bold red]Failed resources:[/bold red]")
                for resource_id, error in result.failed:
                    console.print(f"  • {resource_id}: {error}")
                console.print()

            return 1

    except Exception as e:
        console.print(f"[red]✗ Error during apply: {e}[/red]")
        if args.verbose:
            import traceback
            traceback.print_exc()
        return 1


def command_validate(args):
    """Execute validate command"""
    console.print("[bold blue]Validating templates...[/bold blue]\n")

    orchestrator = init_orchestrator(args, require_credentials=False)
    filters = parse_filters(args)

    try:
        results = orchestrator.validate(**filters)

        # Format and display results
        formatter = PlanFormatter(console, verbose=args.verbose)
        formatter.format_validation_results(results)

        # Return exit code
        has_errors = any(errors for errors in results.values() if errors)
        return 1 if has_errors else 0

    except Exception as e:
        console.print(f"[red]✗ Error during validation: {e}[/red]")
        if args.verbose:
            import traceback
            traceback.print_exc()
        return 1


def command_show(args):
    """Execute show command"""
    console.print("[bold blue]Current State[/bold blue]\n")

    orchestrator = init_orchestrator(args)
    filters = parse_filters(args)

    try:
        state = orchestrator.state_manager.export_to_dict()

        # Filter state if needed
        resource_types = filters.get('resource_types')
        if resource_types:
            filtered_state = {
                rt: resources
                for rt, resources in state.get('resources', {}).items()
                if rt in resource_types
            }
        else:
            filtered_state = state.get('resources', {})

        # Convert dict-of-dicts to dict-of-lists for format_state_view
        # State structure: {resource_type: {resource_name: {metadata}}}
        # Formatter expects: {resource_type: [{name: ..., metadata...}, ...]}
        formatted_state = {}
        for resource_type, resources_dict in filtered_state.items():
            resources_list = []
            for resource_name, metadata in resources_dict.items():
                # Add name to metadata for display
                resource_entry = {'name': resource_name}
                resource_entry.update(metadata)
                resources_list.append(resource_entry)
            formatted_state[resource_type] = resources_list

        # Format output
        if args.format == 'json':
            import json
            console.print_json(json.dumps(filtered_state, indent=2))
        else:
            formatter = PlanFormatter(console, verbose=args.verbose)
            formatter.format_state_view(formatted_state)

        return 0

    except Exception as e:
        console.print(f"[red]✗ Error showing state: {e}[/red]")
        if args.verbose:
            import traceback
            traceback.print_exc()
        return 1


def command_sync(args):
    """Execute sync command to rebuild state from CrowdStrike"""
    console.print("[bold blue]Synchronizing state with CrowdStrike...[/bold blue]\n")
    console.print("[cyan]Fetching currently deployed resources from CrowdStrike API...[/cyan]\n")

    orchestrator = init_orchestrator(args)
    filters = parse_filters(args)

    try:
        # Sync state with CrowdStrike
        stats = orchestrator.sync(**filters)

        # Display results
        console.print("\n[bold]Sync Results:[/bold]")
        console.print(f"  [cyan]Total fetched:[/cyan] {stats['total_fetched']}")
        console.print(f"  [green]Matched templates:[/green] {stats['matched_templates']}")
        console.print(f"  [yellow]Unmatched (no template):[/yellow] {stats['unmatched']}")
        console.print(f"  [blue]State updated:[/blue] {stats['updated']}")

        # Show stale state entries removed
        stale_removed = stats.get('stale_removed', 0)
        if stale_removed > 0:
            console.print(f"  [magenta]Stale state removed:[/magenta] {stale_removed}")

        console.print()

        # Show stale entries that were cleaned up
        stale_names = stats.get('stale_names', [])
        if stale_names:
            console.print(f"[magenta]Removed {len(stale_names)} stale state entries (no template, no remote resource):[/magenta]")
            display_limit = 20
            for name in stale_names[:display_limit]:
                console.print(f"  [magenta]![/magenta] {name}")
            if len(stale_names) > display_limit:
                console.print(f"  [dim]... and {len(stale_names) - display_limit} more[/dim]")
            console.print()

        # Show unmatched remote resources
        if stats['unmatched'] > 0:
            console.print(
                f"[yellow]⚠ {stats['unmatched']} deployed resource(s) have no matching IaC template[/yellow]"
            )
            unmatched_names = stats.get('unmatched_names', [])
            if unmatched_names:
                display_limit = 20
                for name in unmatched_names[:display_limit]:
                    console.print(f"  [yellow]?[/yellow] {name}")
                if len(unmatched_names) > display_limit:
                    console.print(f"  [dim]... and {len(unmatched_names) - display_limit} more[/dim]")
            console.print("[dim]These resources are not tracked in state (IaC only manages resources with templates)[/dim]\n")

        if stats['matched_templates'] > 0:
            console.print(f"[green]✓ State synchronized with {stats['matched_templates']} resources[/green]\n")
        else:
            console.print("[yellow]No resources synced - check filters or verify resources exist in CrowdStrike[/yellow]\n")

        return 0

    except Exception as e:
        console.print(f"[red]✗ Error during sync: {e}[/red]")
        if args.verbose:
            import traceback
            traceback.print_exc()
        return 1


def command_drift(args):
    """Execute drift detection - compare templates, state, and remote CrowdStrike resources"""
    console.print("[bold blue]Detecting drift...[/bold blue]\n")
    console.print("[cyan]Comparing templates, state, and remote CrowdStrike resources...[/cyan]\n")

    orchestrator = init_orchestrator(args)
    filters = parse_filters(args)

    try:
        report = orchestrator.drift(**filters)

        formatter = PlanFormatter(console, verbose=args.verbose)
        formatter.format_drift_report(report)

        # Exit code 1 if drift detected (useful for CI)
        return 1 if report.has_drift else 0

    except Exception as e:
        console.print(f"[red]✗ Error during drift detection: {e}[/red]")
        if args.verbose:
            import traceback
            traceback.print_exc()
        return 1


def command_destroy(args):
    """Execute destroy command"""
    console.print("[bold red]Destroying resources...[/bold red]\n")

    console.print("[yellow]⚠ Destroy command not yet implemented[/yellow]\n")
    console.print("This feature will remove resources from CrowdStrike.\n")

    return 0


def command_import(args):
    """Execute import command — fetch remote resources and generate YAML templates"""
    plan_only = getattr(args, 'import_plan', False)

    if plan_only:
        console.print("[bold blue]Import plan (dry-run)...[/bold blue]\n")
    else:
        console.print("[bold blue]Importing resources from CrowdStrike...[/bold blue]\n")

    orchestrator = init_orchestrator(args)
    filters = parse_filters(args)

    try:
        stats = orchestrator.import_resources(
            resource_types=filters.get('resource_types'),
            names=filters.get('names'),
            plan_only=plan_only
        )

        # Display results
        console.print("\n[bold]Import Results:[/bold]")
        console.print(f"  [cyan]Total fetched from API:[/cyan] {stats['total_fetched']}")
        console.print(f"  [green]{'Would import' if plan_only else 'Imported'}:[/green] {stats['imported']}")
        console.print(f"  [yellow]Skipped (already exist):[/yellow] {stats['skipped_existing']}")
        if stats['skipped_unsupported'] > 0:
            console.print(f"  [dim]Skipped (unsupported):[/dim] {stats['skipped_unsupported']}")
        console.print()

        # Show imported files
        if stats['imported_files']:
            action = "Would write" if plan_only else "Wrote"
            console.print(f"[bold]{action} {len(stats['imported_files'])} template files:[/bold]")
            display_limit = 30
            for f in stats['imported_files'][:display_limit]:
                prefix = "[dim]+[/dim]" if plan_only else "[green]+[/green]"
                console.print(f"  {prefix} resources/{f}")
            if len(stats['imported_files']) > display_limit:
                console.print(f"  [dim]... and {len(stats['imported_files']) - display_limit} more[/dim]")
            console.print()

        # Show errors
        if stats['errors']:
            console.print(f"[red]Errors ({len(stats['errors'])}):[/red]")
            for error in stats['errors'][:10]:
                console.print(f"  [red]![/red] {error}")
            if len(stats['errors']) > 10:
                console.print(f"  [dim]... and {len(stats['errors']) - 10} more[/dim]")
            console.print()

        if stats['imported'] > 0 and not plan_only:
            console.print(
                f"[green]✓ Successfully imported {stats['imported']} resources as YAML templates[/green]\n"
            )
        elif stats['imported'] > 0 and plan_only:
            console.print(
                f"[cyan]→ Run without --plan to import {stats['imported']} resources[/cyan]\n"
            )
        elif stats['imported'] == 0 and stats['skipped_existing'] > 0:
            console.print(
                "[yellow]All matching resources already have template files — nothing to import[/yellow]\n"
            )
        else:
            console.print("[yellow]No resources found to import[/yellow]\n")

        return 1 if stats['errors'] else 0

    except Exception as e:
        console.print(f"[red]✗ Error during import: {e}[/red]")
        if args.verbose:
            import traceback
            traceback.print_exc()
        return 1


def command_validate_query(args):
    """Execute validate-query command to validate a single LogScale query"""
    import yaml

    # Determine query source
    query = None

    if args.query:
        query = args.query
    elif args.file:
        file_path = Path(args.file)
        if not file_path.exists():
            console.print(f"INVALID: File not found: {args.file}")
            return 1
        query = file_path.read_text()
    elif args.template:
        template_path = Path(args.template)
        if not template_path.exists():
            console.print(f"INVALID: Template not found: {args.template}")
            return 1
        try:
            with open(template_path) as f:
                template_data = yaml.safe_load(f)
            # Try detection template format first (search.filter or search.query)
            search = template_data.get('search', {})
            query = search.get('filter') or search.get('query')
            # Fall back to saved search format (queryString)
            if not query:
                query = template_data.get('queryString')
            if not query:
                console.print("INVALID: No search.filter, search.query, or queryString found in template")
                return 1
        except yaml.YAMLError as e:
            console.print(f"INVALID: YAML parse error: {e}")
            return 1
    else:
        console.print("INVALID: Must specify --query, --file, or --template")
        return 1

    # Initialize NGSIEM client and validate
    try:
        from utils.ngsiem_client import NGSIEMClient

        # NGSIEMClient loads credentials automatically if not provided
        ngsiem_client = NGSIEMClient()

        result = ngsiem_client.test_query_syntax(query)

        if result['valid']:
            console.print("VALID")
            return 0
        else:
            console.print(f"INVALID: {result.get('message', 'Unknown error')}")
            return 1

    except Exception as e:
        console.print(f"INVALID: {e}")
        return 1


def command_publish(args):
    """Execute publish command to activate inactive detection rules"""
    console.print("[bold blue]Publishing detection rules...[/bold blue]\n")

    orchestrator = init_orchestrator(args)
    filters = parse_filters(args)

    try:
        # Get detection provider
        from providers import DetectionProvider

        creds = load_credentials()
        from falconpy import APIHarnessV2
        falcon = APIHarnessV2(
            client_id=creds['falcon_client_id'],
            client_secret=creds['falcon_client_secret'],
            base_url=creds.get('base_url', 'US1')
        )

        detection_provider = DetectionProvider(falcon_client=falcon)

        # Get resource IDs from name filters if provided
        resource_ids = None
        if filters.get('names'):
            # Convert name patterns to detection resource IDs
            resource_ids = [f"detection.{name}" for name in filters['names']]

        # Find inactive rules
        console.print("[cyan]Finding inactive detection rules to publish...[/cyan]\n")

        # Call publish method
        successful, failed = detection_provider.publish(resource_ids=resource_ids)

        # Display what will be published
        total = len(successful) + len(failed)
        if total == 0:
            console.print("[yellow]No inactive detection rules found to publish[/yellow]\n")
            return 0

        console.print(f"[bold]Found {total} inactive detection rule(s):[/bold]")
        for resource_id in successful + [f for f, _ in failed]:
            rule_name = resource_id.split('.', 1)[1] if '.' in resource_id else resource_id
            console.print(f"  • {rule_name}")
        console.print()

        # Confirm unless auto-approve
        if not args.auto_approve:
            if not Confirm.ask("[yellow]Do you want to activate these rules for production?[/yellow]"):
                console.print("\n[dim]Publish cancelled.[/dim]\n")
                return 0

        # Display results
        if successful:
            console.print(f"\n[green]✓ Successfully activated {len(successful)} detection rule(s)[/green]")
            for resource_id in successful:
                rule_name = resource_id.split('.', 1)[1] if '.' in resource_id else resource_id
                console.print(f"  • {rule_name}")
            console.print()

        if failed:
            console.print(f"\n[red]✗ Failed to activate {len(failed)} detection rule(s)[/red]")
            for resource_id, error in failed:
                rule_name = resource_id.split('.', 1)[1] if '.' in resource_id else resource_id
                console.print(f"  • {rule_name}: {error}")
            console.print()

        return 1 if failed else 0

    except Exception as e:
        console.print(f"[red]✗ Error during publish: {e}[/red]")
        if args.verbose:
            import traceback
            traceback.print_exc()
        return 1


def main():
    """Main entry point"""
    args = parse_args()

    # Set log level based on verbose flag
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    # Display header
    console.print(f"\n[bold cyan]CrowdStrike Unified Resource Deployment[/bold cyan]")
    console.print(f"[dim]{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}[/dim]\n")

    # Route to command handler
    command_handlers = {
        'plan': command_plan,
        'apply': command_apply,
        'validate': command_validate,
        'validate-query': command_validate_query,
        'show': command_show,
        'sync': command_sync,
        'drift': command_drift,
        'destroy': command_destroy,
        'import': command_import,
        'publish': command_publish
    }

    if not args.command:
        console.print("[red]Error: No command specified[/red]")
        console.print("Run with --help for usage information\n")
        return 1

    handler = command_handlers.get(args.command)
    if not handler:
        console.print(f"[red]Error: Unknown command: {args.command}[/red]\n")
        return 1

    # Execute command
    return handler(args)


if __name__ == '__main__':
    try:
        exit_code = main()
        sys.exit(exit_code)
    except KeyboardInterrupt:
        console.print("\n[yellow]Interrupted by user[/yellow]\n")
        sys.exit(130)
    except Exception as e:
        console.print(f"\n[red]Fatal error: {e}[/red]\n")
        import traceback
        traceback.print_exc()
        sys.exit(1)
