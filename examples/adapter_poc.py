#!/usr/bin/env python3
"""
Provider Adapter Proof of Concept

This script demonstrates how the ProviderAdapter bridges the existing
detection deployment system with the new provider-based architecture.
"""

import sys
from pathlib import Path

# Add scripts directory to path
SCRIPTS_DIR = Path(__file__).parent.parent / "scripts"
sys.path.insert(0, str(SCRIPTS_DIR))

import json
from unittest.mock import Mock
from core.provider_adapter import ProviderAdapter
from core import ResourceState
import tempfile


def example_1_legacy_to_v3_conversion():
    """Example 1: Converting legacy v2.0 state to v3.0"""
    print("=" * 60)
    print("Example 1: Legacy State Conversion")
    print("=" * 60)

    # Create mock Falcon client
    mock_falcon = Mock()

    # Create temporary state file
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        state_path = Path(f.name)
        json.dump({
            "version": "3.0",
            "last_updated": "2024-01-01T00:00:00Z",
            "metadata": {},
            "resources": {},
            "resource_graph": {"nodes": [], "edges": []}
        }, f)

    # Initialize adapter
    adapter = ProviderAdapter(mock_falcon, state_path)

    # Legacy v2.0 state (what exists today)
    legacy_state = {
        'version': '2.0',
        'last_updated': '2024-01-01T00:00:00Z',
        'rules': {
            'aws_root_login': {
                'rule_id': 'abc123',
                'content_hash': 'hash123',
                'template_path': 'rules/aws/root_login.yaml',
                'deployed_at': '2024-01-01T00:00:00Z',
                'last_modified': '2024-01-01T00:00:00Z',
                'status': 'active',
                'workflow_created': True,
                'workflow_id': 'wf456',
                'workflow_name': 'aws_root_login_notify',
                'workflow_enabled': True
            }
        }
    }

    print("\nLegacy v2.0 State:")
    print(json.dumps(legacy_state, indent=2))

    # Import legacy state
    adapter.import_legacy_state(legacy_state)

    # Show converted v3.0 state
    v3_state = adapter.state_manager.export_to_dict()
    print("\nConverted v3.0 State:")
    print(json.dumps(v3_state, indent=2))

    # Show resource extraction
    detection = adapter.state_manager.get_resource('detection', 'aws_root_login')
    print("\nExtracted Detection Resource:")
    print(f"  Type: {detection.type}")
    print(f"  ID: {detection.id}")
    print(f"  Template: {detection.template_path}")
    print(f"  Metadata: {detection.provider_metadata}")

    # Clean up
    state_path.unlink()
    print("\n✓ Example 1 Complete\n")


def example_2_bidirectional_conversion():
    """Example 2: Bidirectional conversion between formats"""
    print("=" * 60)
    print("Example 2: Bidirectional Conversion")
    print("=" * 60)

    # Create mock Falcon client
    mock_falcon = Mock()

    # Create temporary state file
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        state_path = Path(f.name)
        json.dump({
            "version": "3.0",
            "last_updated": "2024-01-01T00:00:00Z",
            "metadata": {},
            "resources": {},
            "resource_graph": {"nodes": [], "edges": []}
        }, f)

    # Initialize adapter
    adapter = ProviderAdapter(mock_falcon, state_path)

    # Create v3.0 ResourceState
    resource_state = ResourceState(
        type='detection',
        id='rule789',
        content_hash='newhash',
        template_path='rules/test/example.yaml',
        deployed_at='2024-01-15T10:00:00Z',
        last_modified='2024-01-15T10:00:00Z',
        provider_metadata={
            'rule_id': 'rule789',
            'status': 'active',
            'workflow_created': False
        },
        dependencies=['saved_search.base_query']
    )

    print("\nOriginal v3.0 ResourceState:")
    print(f"  Type: {resource_state.type}")
    print(f"  ID: {resource_state.id}")
    print(f"  Dependencies: {resource_state.dependencies}")
    print(f"  Metadata: {resource_state.provider_metadata}")

    # Convert to legacy format
    legacy_format = adapter.convert_resource_state_to_legacy(resource_state)
    print("\nConverted to Legacy v2.0 Format:")
    print(json.dumps(legacy_format, indent=2))

    # Convert back to v3.0
    converted_back = adapter.convert_legacy_state_to_resource_state(
        legacy_format,
        'example_rule'
    )
    print("\nConverted Back to v3.0 ResourceState:")
    print(f"  Type: {converted_back.type}")
    print(f"  ID: {converted_back.id}")
    print(f"  Metadata: {converted_back.provider_metadata}")

    # Clean up
    state_path.unlink()
    print("\n✓ Example 2 Complete\n")


def example_3_export_legacy_state():
    """Example 3: Export v3.0 state as legacy v2.0 for compatibility"""
    print("=" * 60)
    print("Example 3: Export as Legacy Format")
    print("=" * 60)

    # Create mock Falcon client
    mock_falcon = Mock()

    # Create temporary state file
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        state_path = Path(f.name)
        json.dump({
            "version": "3.0",
            "last_updated": "2024-01-01T00:00:00Z",
            "metadata": {},
            "resources": {},
            "resource_graph": {"nodes": [], "edges": []}
        }, f)

    # Initialize adapter
    adapter = ProviderAdapter(mock_falcon, state_path)

    # Add multiple resources to v3.0 state
    resources = [
        ResourceState(
            type='detection',
            id='rule1',
            content_hash='hash1',
            template_path='rules/aws/s3_public.yaml',
            deployed_at='2024-01-10T00:00:00Z',
            last_modified='2024-01-10T00:00:00Z',
            provider_metadata={'rule_id': 'rule1', 'status': 'active'},
            dependencies=[]
        ),
        ResourceState(
            type='detection',
            id='rule2',
            content_hash='hash2',
            template_path='rules/azure/admin_login.yaml',
            deployed_at='2024-01-11T00:00:00Z',
            last_modified='2024-01-11T00:00:00Z',
            provider_metadata={'rule_id': 'rule2', 'status': 'inactive'},
            dependencies=['lookup_file.trusted_ips']
        ),
    ]

    for i, resource in enumerate(resources, 1):
        adapter.state_manager.set_resource('detection', f'rule_{i}', resource)

    # Export as legacy format
    legacy_state = adapter.get_legacy_state_dict()

    print("\nExported Legacy v2.0 State:")
    print(json.dumps(legacy_state, indent=2))

    print(f"\nTotal Rules: {len(legacy_state['rules'])}")
    for rule_name, rule_data in legacy_state['rules'].items():
        print(f"  - {rule_name}: {rule_data['template_path']} ({rule_data['status']})")

    # Clean up
    state_path.unlink()
    print("\n✓ Example 3 Complete\n")


def example_4_planning_with_providers():
    """Example 4: Using providers for planning through adapter"""
    print("=" * 60)
    print("Example 4: Provider-Based Planning")
    print("=" * 60)

    # Create mock Falcon client
    mock_falcon = Mock()

    # Create temporary state file
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        state_path = Path(f.name)
        json.dump({
            "version": "3.0",
            "last_updated": "2024-01-01T00:00:00Z",
            "metadata": {},
            "resources": {},
            "resource_graph": {"nodes": [], "edges": []}
        }, f)

    # Initialize adapter
    adapter = ProviderAdapter(mock_falcon, state_path)

    # Mock provider methods
    from unittest.mock import patch
    from core import ResourceAction, ResourceChange

    with patch.object(adapter.detection_provider, 'validate_template', return_value=[]):
        with patch.object(adapter.detection_provider, 'plan_create') as mock_create:
            # Configure mock
            mock_create.return_value = ResourceChange(
                action=ResourceAction.CREATE,
                resource_type='detection',
                resource_name='new_rule',
                resource_id=None,
                old_value=None,
                new_value={'name': 'New Rule'},
                changes=None,
                template_path='rules/new.yaml'
            )

            # Templates to deploy
            templates = {
                'new_rule': {
                    'name': 'New Rule',
                    'description': 'A new detection rule',
                    'severity': 50,
                    'search': {
                        'query': '#event_simpleName=ProcessRollup2'
                    },
                    '_template_path': 'rules/new.yaml'
                }
            }

            # Generate plan
            plan = adapter.plan_detection_changes(templates)

            print("\nGenerated Plan:")
            print(f"  Creates: {len(plan['create'])}")
            print(f"  Updates: {len(plan['update'])}")
            print(f"  Deletes: {len(plan['delete'])}")

            if plan['create']:
                print("\nDetailed Create Plan:")
                for change in plan['create']:
                    print(f"  - Action: {change.action}")
                    print(f"    Resource: {change.resource_type}.{change.resource_name}")
                    print(f"    Template: {change.template_path}")

    # Clean up
    state_path.unlink()
    print("\n✓ Example 4 Complete\n")


def main():
    """Run all examples"""
    print("\n" + "=" * 60)
    print("Provider Adapter - Proof of Concept Examples")
    print("=" * 60 + "\n")

    try:
        example_1_legacy_to_v3_conversion()
        example_2_bidirectional_conversion()
        example_3_export_legacy_state()
        example_4_planning_with_providers()

        print("=" * 60)
        print("All Examples Completed Successfully!")
        print("=" * 60)

    except Exception as e:
        print(f"\n❌ Error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
