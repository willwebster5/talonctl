"""talonctl show — display current state."""

import click

from talonctl.commands._common import (
    console, filter_options, state_options, parse_filters, init_orchestrator,
)


@click.command()
@filter_options
@state_options
@click.option('--format', 'output_format', type=click.Choice(['table', 'json']), default='table', help='Output format')
@click.pass_context
def show(ctx, resources, tags, names, state_file, output_format):
    """Display current state."""
    console.print("[bold blue]Current State[/bold blue]\n")
    verbose = ctx.obj.get('verbose', False)

    orchestrator = init_orchestrator(state_file=state_file)
    filters = parse_filters(resources, tags, names)

    try:
        state = orchestrator.state_manager.export_to_dict()

        # Filter state if needed
        resource_types = filters.get('resource_types')
        if resource_types:
            filtered_state = {
                rt: res
                for rt, res in state.get('resources', {}).items()
                if rt in resource_types
            }
        else:
            filtered_state = state.get('resources', {})

        # Convert dict-of-dicts to dict-of-lists for format_state_view
        formatted_state = {}
        for resource_type, resources_dict in filtered_state.items():
            resources_list = []
            for resource_name, metadata in resources_dict.items():
                resource_entry = {'name': resource_name}
                resource_entry.update(metadata)
                resources_list.append(resource_entry)
            formatted_state[resource_type] = resources_list

        # Format output
        if output_format == 'json':
            import json
            console.print_json(json.dumps(filtered_state, indent=2))
        else:
            from talonctl.core import PlanFormatter
            formatter = PlanFormatter(console, verbose=verbose)
            formatter.format_state_view(formatted_state)

    except Exception as e:
        console.print(f"[red]✗ Error showing state: {e}[/red]")
        if verbose:
            import traceback
            traceback.print_exc()
        ctx.exit(1)
