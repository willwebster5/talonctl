#!/usr/bin/env python3
"""
CrowdStrike Template Discovery Tool

Discovers CrowdStrike correlation rule templates that are not yet implemented in IaC.
Fetches templates from the NGSIEM lookup file and performs fuzzy matching against
local rules to identify new and updated templates.
"""

import sys
import os
import re
import csv
import json
import yaml
import argparse
import logging
import requests
from pathlib import Path
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, asdict
from io import StringIO
from collections import defaultdict

from talonctl.utils.auth import load_credentials
from talonctl.utils.template_matcher import TemplateMatcher

try:
    from falconpy import OAuth2
    from rich.console import Console
    from rich.table import Table
    from rich.progress import Progress, SpinnerColumn, TextColumn
    from rich.panel import Panel
    from rich import print as rprint
except ImportError as e:
    print(f"Error importing required modules: {e}")
    print("Please install: pip install falconpy rich")
    sys.exit(1)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

console = Console(width=200 if os.getenv('CI') else None, force_terminal=True)


@dataclass
class Template:
    """Represents a CrowdStrike correlation rule template"""
    id: str
    name: str
    description: str
    severity: Any          # str from CSV ("high"), int from API (70)
    vendors: List[str]
    data_sources: List[str]
    mitre_attack: List[str]
    created_timestamp: str
    modified_timestamp: Optional[str]
    query: str
    schedule: str
    search_window_start: str
    outcome: str
    type: Optional[str] = None   # NEW — API only; None on CSV path

    @property
    def severity_numeric(self) -> int:
        """Convert severity to numeric value"""
        if isinstance(self.severity, int):
            return self.severity
        severity_map = {
            'info': 10,
            'low': 30,
            'medium': 50,
            'high': 70,
            'critical': 90
        }
        return severity_map.get(str(self.severity).lower(), 50)
    
    @property
    def mitre_tactics(self) -> List[str]:
        """Extract MITRE tactics from mitre_attack field"""
        tactics = []
        for attack in self.mitre_attack:
            if ':' in attack:
                tactic = attack.split(':')[0].strip()
                if tactic:
                    tactics.append(tactic)
        return tactics
    
    @property
    def mitre_techniques(self) -> List[str]:
        """Extract MITRE techniques from mitre_attack field"""
        techniques = []
        for attack in self.mitre_attack:
            if ':' in attack:
                technique = attack.split(':', 1)[1].strip()
                if technique:
                    techniques.append(technique)
        return techniques


# Base URL mapping for CrowdStrike regions
_FALCON_BASE_URLS = {
    'US1': 'https://api.crowdstrike.com',
    'US2': 'https://api.us-2.crowdstrike.com',
    'EU1': 'https://api.eu-1.crowdstrike.com',
    'GOV1': 'https://api.laggar.gcw.crowdstrike.com',
}


class TemplateDiscovery:
    """Main template discovery system"""

    def __init__(self, match_threshold: float = 80.0, dry_run: bool = False, output_format: str = 'console'):
        """
        Initialize the discovery system

        Args:
            match_threshold: Minimum match score to consider a template matched
            dry_run: If True, don't create any files
            output_format: Output format ('console' or 'json')
        """
        self.match_threshold = match_threshold
        self.dry_run = dry_run
        self.output_format = output_format
        self.matcher = TemplateMatcher(match_threshold)

        # Create conditional console for output formatting
        if self.output_format == 'json':
            # Create a null console that doesn't output anything
            from rich.console import Console
            import io
            self.console = Console(file=io.StringIO(), force_terminal=False)
        else:
            self.console = console
        
        # Paths
        self.project_root = Path(__file__).resolve().parent.parent
        self.rules_dir = self.project_root / 'resources' / 'detections'
        self.review_dir = self.project_root / 'templates_review'
        self.manifest_file = self.review_dir / '.manifest.yaml'
        self.state_file = self.project_root / '.crowdstrike' / 'deployed_state.json'
        
        # Storage
        self.templates: List[Template] = []
        self.local_rules: List[Dict] = []
        self.deployed_state: Dict = {}
        self.manifest: Dict = {}
        
        # Statistics
        self.stats = {
            'total_templates': 0,
            'matched': 0,
            'new': 0,
            'updated': 0,
            'skipped': 0,
            'generated': 0
        }
    
    def load_credentials(self) -> Dict:
        """Load FalconPy credentials"""
        try:
            return load_credentials()
        except Exception as e:
            logger.error(f"Failed to load credentials: {e}")
            raise
    
    def parse_csv_data(self, csv_content: str) -> List[Template]:
        """
        Parse CSV content into Template objects

        Expected CSV format from CrowdStrike NGSIEM lookup file:
        - vendors: Simple comma-separated format (e.g., "CrowdStrike, AWS")
        - data_sources: Quoted list format (e.g., "source1","source2")
        - mitre_attack: Quoted list format (e.g., "tactic1:technique1","tactic2:technique2")

        Args:
            csv_content: CSV file content from ngsiem_correlation_rule_templates.csv

        Returns:
            List of Template objects
        """
        templates = []
        csv_reader = csv.DictReader(StringIO(csv_content))
        
        for row in csv_reader:
            try:
                # Parse complex fields
                vendors = self._parse_quoted_list(row.get('vendors', ''))
                data_sources = self._parse_quoted_list(row.get('data_sources', ''))
                mitre_attack = self._parse_quoted_list(row.get('mitre_attack', ''))
                
                template = Template(
                    id=row.get('id', ''),
                    name=row.get('name', ''),
                    description=row.get('description', ''),
                    severity=row.get('severity', 'Medium'),
                    vendors=vendors,
                    data_sources=data_sources,
                    mitre_attack=mitre_attack,
                    created_timestamp=row.get('created_timestamp', ''),
                    modified_timestamp=row.get('modified_timestamp') or None,
                    query=row.get('query', ''),
                    schedule=row.get('schedule', '1h'),
                    search_window_start=row.get('search_window_start', '-70m'),
                    outcome=row.get('outcome', 'Detection')
                )
                templates.append(template)
            except Exception as e:
                logger.warning(f"Failed to parse template row: {e}")
                continue
        
        return templates

    def _parse_api_template(self, entity: Dict) -> Optional['Template']:
        """
        Parse a single CRT API entity into a Template object.

        Normalizes MITRE from [{tactic_id, technique_id}] to ["TA0001:T1078"] strings
        to keep all downstream code (YAML generator, fuzzy matcher) unchanged.
        """
        try:
            mitre_raw = entity.get('mitre_attack', [])
            mitre_attack = [
                f"{m['tactic_id']}:{m['technique_id']}"
                for m in (mitre_raw or [])
                if m.get('tactic_id') and m.get('technique_id')
            ]

            search = entity.get('search') or {}
            operation = entity.get('operation') or {}
            schedule_def = (operation.get('schedule') or {}).get('definition', '@every 1h0m')

            return Template(
                id=entity['id'],
                name=entity.get('name', ''),
                description=entity.get('description', ''),
                severity=entity.get('severity', 50),
                vendors=entity.get('vendors') or [],
                data_sources=[],
                mitre_attack=mitre_attack,
                created_timestamp=entity.get('created_on', ''),
                modified_timestamp=entity.get('last_updated_on') or None,
                query=search.get('filter', ''),
                schedule=schedule_def,
                search_window_start=search.get('lookback', '-70m'),
                outcome=search.get('outcome', 'detection'),
                type=entity.get('type'),
            )
        except Exception as e:
            logger.warning(f"Failed to parse API template entity id={entity.get('id', '<unknown>')}: {e}")
            return None

    def _build_fql_filter(self,
                          vendor: Optional[List[str]] = None,
                          days_back: Optional[int] = None,
                          _now=None) -> Optional[str]:
        """
        Build an FQL filter string for the CRT API query endpoint.

        Supported server-side filters: vendor (exact match), last_updated_on (range).
        Severity, MITRE, and exclude_experimental remain in-memory only.

        Args:
            vendor: List of vendor names to filter on. Pass ['all'] to skip filtering.
            days_back: Only return templates updated within this many days.
            _now: Override current time (for testing). Defaults to datetime.now(utc).
        """
        clauses = []

        if days_back is not None:
            now = _now or datetime.now(timezone.utc)
            cutoff = now - timedelta(days=days_back)
            clauses.append(f"last_updated_on:>'{cutoff.strftime('%Y-%m-%dT%H:%M:%SZ')}'")

        if vendor and 'all' not in [v.lower() for v in vendor]:
            if len(vendor) == 1:
                clauses.append(f"vendor:'{vendor[0]}'")
            else:
                vendor_parts = ','.join(f"vendor:'{v}'" for v in vendor)
                clauses.append(f"({vendor_parts})")

        return '+'.join(clauses) if clauses else None

    def fetch_from_api(self, fql_filter: Optional[str] = None) -> List['Template']:
        """
        Fetch templates from the CRT API.

        Paginates /queries/templates/v1 for IDs, then batch-fetches
        /entities/templates/v1 in groups of 100. Token obtained once
        before pagination.

        Raises ValueError on auth failure or non-200 API response.
        Caller is responsible for falling back to CSV on exception.
        """
        creds = self.load_credentials()

        # Obtain OAuth token once — valid for ~30 min, well within a full catalog fetch
        auth = OAuth2(
            client_id=creds.get('falcon_client_id'),
            client_secret=creds.get('falcon_client_secret'),
            base_url=creds.get('base_url', 'US1')
        )
        token_response = auth.token()
        if token_response['status_code'] != 201:
            raise ValueError(f"Failed to authenticate: {token_response.get('status_code')}")

        access_token = token_response['body']['access_token']

        # Resolve base URL
        region = str(creds.get('base_url', 'US1')).upper()
        api_base = _FALCON_BASE_URLS.get(region, creds.get('base_url', 'https://api.crowdstrike.com'))
        headers = {'Authorization': f'Bearer {access_token}'}

        # --- Step 1: Paginated ID query ---
        all_ids: List[str] = []
        offset = 0
        limit = 100

        while True:
            params: Dict[str, Any] = {'limit': limit, 'offset': offset, 'sort': 'last_updated_on|desc'}
            if fql_filter:
                params['filter'] = fql_filter

            resp = requests.get(
                f'{api_base}/correlation-rules/queries/templates/v1',
                headers=headers,
                params=params,
                timeout=30
            )
            if resp.status_code != 200:
                raise ValueError(
                    f"CRT query API returned {resp.status_code}: {resp.text[:200]}"
                )

            body = resp.json()
            ids = body.get('resources') or []
            if not ids:
                break

            all_ids.extend(ids)
            total = (body.get('meta') or {}).get('pagination', {}).get('total', 0)
            if len(all_ids) >= total:
                break

            offset += len(ids)

        if not all_ids:
            self.console.print("[dim]No templates returned by API[/dim]")
            return []

        # --- Step 2: Batch entity fetch (100 IDs per request) ---
        templates: List[Template] = []
        for i in range(0, len(all_ids), 100):
            batch = all_ids[i:i + 100]
            resp = requests.get(
                f'{api_base}/correlation-rules/entities/templates/v1',
                headers=headers,
                params={'ids': batch},
                timeout=30
            )
            if resp.status_code != 200:
                raise ValueError(
                    f"CRT entities API returned {resp.status_code}: {resp.text[:200]}"
                )
            for entity in resp.json().get('resources') or []:
                tmpl = self._parse_api_template(entity)
                if tmpl:
                    templates.append(tmpl)

        self.console.print(f"✓ Fetched [green]{len(templates)}[/green] templates from CRT API")
        return templates

    def _parse_quoted_list(self, value: str) -> List[str]:
        """
        Parse a CSV list field that may be in different formats:
        - Quoted list format: "item1","item2","item3"
        - Simple comma-separated: item1, item2, item3
        """
        if not value:
            return []

        # Check if this is a quoted list format with internal quotes
        if '","' in value:
            # Handle quoted list format: "item1","item2","item3"
            value = value.strip('"')
            items = re.split(r'",\s*"', value)
            return [item.strip('"') for item in items if item]
        else:
            # Handle simple comma-separated format: item1, item2, item3
            return [item.strip() for item in value.split(',') if item.strip()]
    
    def load_local_rules(self) -> List[Dict]:
        """Load all local YAML rules"""
        rules = []
        
        for yaml_file in self.rules_dir.rglob('*.yaml'):
            try:
                with open(yaml_file, 'r') as f:
                    rule_data = yaml.safe_load(f)
                    if rule_data and 'name' in rule_data:
                        rule_data['file_path'] = str(yaml_file.relative_to(self.project_root))
                        rules.append(rule_data)
            except Exception as e:
                logger.warning(f"Failed to load rule {yaml_file}: {e}")
                continue
        
        return rules
    
    def load_manifest(self) -> Dict:
        """Load the manifest of previously generated templates"""
        if not self.manifest_file.exists():
            return {'templates': {}}

        try:
            with open(self.manifest_file, 'r') as f:
                return yaml.safe_load(f) or {'templates': {}}
        except Exception as e:
            logger.warning(f"Failed to load manifest: {e}")
            return {'templates': {}}

    def load_deployed_state(self) -> Dict:
        """Load the deployed state file to check for already-deployed detections"""
        if not self.state_file.exists():
            logger.debug("No deployed state file found")
            return {}

        try:
            with open(self.state_file, 'r') as f:
                state = json.load(f)
                # Extract detection resources from v3.0 state format
                detections = state.get('resources', {}).get('detection', {})
                logger.debug(f"Loaded {len(detections)} deployed detections from state file")
                return detections
        except json.JSONDecodeError as e:
            logger.warning(f"Failed to parse deployed state file: {e}")
            return {}
        except Exception as e:
            logger.warning(f"Failed to load deployed state: {e}")
            return {}
    
    def save_manifest(self):
        """Save the manifest file"""
        if self.dry_run:
            return
        
        self.review_dir.mkdir(parents=True, exist_ok=True)
        
        with open(self.manifest_file, 'w') as f:
            yaml.dump(self.manifest, f, sort_keys=False, default_flow_style=False)
    
    def apply_filters(self, templates: List[Template],
                     vendor: Optional[List[str]] = None,
                     severity: Optional[List[str]] = None,
                     days_back: Optional[int] = None,
                     mitre_tactic: Optional[List[str]] = None,
                     mitre_technique: Optional[List[str]] = None) -> List[Template]:
        """Apply filters to template list"""
        filtered = templates
        original_count = len(templates)

        # Vendor filter
        if vendor and 'all' not in [v.lower() for v in vendor]:
            before_vendor = len(filtered)
            filtered = [t for t in filtered if any(
                v.lower() in [vendor.lower() for vendor in t.vendors]
                for v in vendor
            )]
            after_vendor = len(filtered)
            logger.debug(f"Vendor filter: {before_vendor} -> {after_vendor} templates (filter: {vendor})")

            # Debug: log some examples of excluded templates
            if before_vendor > after_vendor and logger.isEnabledFor(logging.DEBUG):
                excluded = [t for t in templates if not any(
                    v.lower() in [vendor.lower() for vendor in t.vendors]
                    for v in vendor
                )][:5]  # First 5 excluded
                for template in excluded:
                    logger.debug(f"  Excluded '{template.name}' (vendors: {template.vendors})")
                if len(excluded) > 5:
                    logger.debug(f"  ... and {len(excluded) - 5} more excluded templates")
        
        # Severity filter
        if severity:
            severity_lower = [s.lower() for s in severity]
            # Reverse map for int severities returned by the API (e.g., 70 -> "high")
            _int_to_label = {10: 'info', 30: 'low', 50: 'medium', 70: 'high', 90: 'critical'}

            def _severity_label(t: 'Template') -> str:
                if isinstance(t.severity, int):
                    return _int_to_label.get(t.severity, str(t.severity)).lower()
                return str(t.severity).lower()

            filtered = [t for t in filtered if _severity_label(t) in severity_lower]
        
        # Date filter
        if days_back:
            cutoff_date = datetime.now(timezone.utc) - timedelta(days=days_back)
            filtered_by_date = []
            
            for t in filtered:
                # Check both created and modified dates
                dates_to_check = []
                
                if t.created_timestamp:
                    try:
                        created = datetime.fromisoformat(t.created_timestamp.replace('Z', '+00:00'))
                        dates_to_check.append(created)
                    except:
                        pass
                
                if t.modified_timestamp:
                    try:
                        modified = datetime.fromisoformat(t.modified_timestamp.replace('Z', '+00:00'))
                        dates_to_check.append(modified)
                    except:
                        pass
                
                # Include if any date is after cutoff
                if any(d >= cutoff_date for d in dates_to_check):
                    filtered_by_date.append(t)
            
            filtered = filtered_by_date
        
        # MITRE tactic filter
        if mitre_tactic:
            filtered = [t for t in filtered if any(
                tactic in t.mitre_tactics for tactic in mitre_tactic
            )]
        
        # MITRE technique filter
        if mitre_technique:
            filtered = [t for t in filtered if any(
                technique in t.mitre_techniques for technique in mitre_technique
            )]
        
        return filtered
    
    def generate_filename(self, template_name: str, prefix: str = "") -> str:
        """Generate a filename from template name"""
        name = template_name.lower()
        
        # Handle vendor prefixes - convert to underscore
        for vendor in ['aws', 'microsoft', 'google', 'crowdstrike', 'generic', 'sase']:
            pattern = f'^{vendor}\\s*[-–—]\\s*'
            if re.match(pattern, name, re.I):
                name = re.sub(pattern, f'{vendor}_', name, flags=re.I)
                break
        
        # Replace separators with underscores
        name = re.sub(r'\s*[-–—]\s*', '_', name)  # Various dashes
        name = re.sub(r'\s+', '_', name)           # Spaces
        name = re.sub(r'[^\w_]', '', name)         # Remove special chars
        name = re.sub(r'_+', '_', name)            # Collapse multiple underscores
        name = name.strip('_')
        
        if prefix:
            # Clean up prefix
            prefix = prefix.replace('(', '').replace(')', '').lower()
            name = f"{prefix}_{name}"
        
        return f"{name}.yaml"
    
    def generate_yaml_content(self, template: Template, is_update: bool = False) -> str:
        """Generate YAML content for a template"""
        # Clean up description
        description = template.description.strip()
        if is_update:
            description = f"[UPDATED TEMPLATE - Review changes carefully]\n\n{description}"

        # Prepare YAML content
        yaml_content = f"""# Generated from CrowdStrike template: {template.id}
# Original name: {template.name}
# Generated on: {datetime.now().strftime('%Y-%m-%d')}
{f'# UPDATED: Template modified on {template.modified_timestamp}' if is_update else ''}

name: {template.name}
template_id: {template.id}
description: |
  {description.replace(chr(10), chr(10) + '  ')}

severity: {template.severity_numeric}  # {template.severity}
status: inactive  # Default to inactive for review"""

        # Add MITRE ATT&CK information - ALWAYS use Format 1 (array format)
        if template.mitre_attack:
            # Build array of "tactic:technique" strings (Format 1 - standard)
            formatted_entries = []
            for attack in template.mitre_attack:
                if ':' in attack:
                    tactic_part, technique_part = attack.split(':', 1)
                    # Remove any embedded quotes from CSV parsing
                    tactic_part = tactic_part.strip().strip('"').strip("'")
                    technique_part = technique_part.strip().strip('"').strip("'")

                    # Extract IDs using MitreProcessor
                    from utils.mitre_processor import MitreProcessor
                    tactic_id = MitreProcessor.extract_id(tactic_part)
                    technique_id = MitreProcessor.extract_id(technique_part)

                    formatted_entries.append(f'"{tactic_id}:{technique_id}"')

            if formatted_entries:
                yaml_content += f"\nmitre_attack: [{', '.join(formatted_entries)}]"
            else:
                # No valid MITRE data parsed - leave empty for manual population
                yaml_content += "\nmitre_attack:"
        else:
            # No MITRE data - leave empty for manual population
            yaml_content += "\nmitre_attack:"

        yaml_content += f"""

search:
  filter: |
    {template.query.replace(chr(10), chr(10) + '    ')}
  lookback: 1h10m
  trigger_mode: summary
  outcome: {template.outcome.lower()}

operation:
  schedule:
    definition: '@every {template.schedule}'

# Template metadata (remove before deployment)
_template_metadata:
  created_timestamp: {template.created_timestamp}
  last_updated_on: {template.modified_timestamp or 'null'}
  vendors: {json.dumps(template.vendors)}
  data_sources: {json.dumps(template.data_sources)}
  mitre_attack: {json.dumps(template.mitre_attack)}
{f"  type: {template.type}" if template.type else ""}
"""
        return yaml_content
    
    def process_template(self, template: Template) -> Optional[str]:
        """
        Process a single template - check if it needs to be generated

        Returns:
            Action taken: 'new', 'updated', 'skipped', or None
        """
        # Check for match with local rules
        best_match, score = self.matcher.find_best_match(template.name, self.local_rules)

        if self.matcher.is_match(score):
            self.stats['matched'] += 1
            logger.debug(f"Template '{template.name}' matched with '{best_match['name']}' (score: {score:.1f})")
            return None

        # Check for match with deployed state (detection resources)
        if self.deployed_state:
            # Build list of deployed detection "rules" with names for matching
            deployed_rules = []
            for resource_name, resource_data in self.deployed_state.items():
                # Try to get the actual detection name from the template path
                template_path = resource_data.get('template_path', '')
                if template_path:
                    # Try to load the template to get the name
                    template_file_path = self.project_root / template_path
                    if template_file_path.exists():
                        try:
                            with open(template_file_path, 'r') as f:
                                deployed_rule_data = yaml.safe_load(f)
                                if deployed_rule_data and 'name' in deployed_rule_data:
                                    deployed_rules.append(deployed_rule_data)
                        except:
                            pass

            if deployed_rules:
                deployed_match, deployed_score = self.matcher.find_best_match(template.name, deployed_rules)
                if self.matcher.is_match(deployed_score):
                    self.stats['matched'] += 1
                    logger.debug(f"Template '{template.name}' matched with deployed detection '{deployed_match['name']}' (score: {deployed_score:.1f})")
                    return None

        # Check if we've generated this template before
        if template.id in self.manifest.get('templates', {}):
            prev_entry = self.manifest['templates'][template.id]
            prev_updated = prev_entry.get('last_updated_on') or prev_entry.get('modified_timestamp')

            # Check if template has been updated
            if template.modified_timestamp and prev_updated != template.modified_timestamp:
                self.stats['updated'] += 1
                return 'updated'
            else:
                self.stats['skipped'] += 1
                logger.debug(f"Template '{template.name}' already generated and unchanged")
                return 'skipped'

        # New template
        self.stats['new'] += 1
        return 'new'
    
    def generate_template_file(self, template: Template, action: str) -> bool:
        """Generate a YAML file for a template"""
        if self.dry_run:
            self.console.print(f"  [dim]Would create: {template.name}[/dim]")
            return True
        
        # Determine vendor for directory
        vendor = 'generic'
        if template.vendors:
            vendor = template.vendors[0].lower()
        
        # Create directory structure
        vendor_dir = self.review_dir / vendor
        vendor_dir.mkdir(parents=True, exist_ok=True)
        
        # Generate filename
        prefix = "(updated)" if action == 'updated' else ""
        filename = self.generate_filename(template.name, prefix)
        file_path = vendor_dir / filename
        
        # Generate content
        yaml_content = self.generate_yaml_content(template, is_update=(action == 'updated'))
        
        # Write file
        try:
            file_path.write_text(yaml_content)
            try:
                display_path = file_path.relative_to(self.project_root)
            except ValueError:
                display_path = file_path
            self.console.print(f"  ✓ Created: {display_path}")

            # Update manifest
            self.manifest['templates'][template.id] = {
                'name': template.name,
                'filename': str(file_path.relative_to(self.review_dir)),
                'generated_at': datetime.now(timezone.utc).isoformat(),
                'last_updated_on': template.modified_timestamp,
                'vendor': vendor,
                'action': action
            }
            
            self.stats['generated'] += 1
            return True
            
        except Exception as e:
            self.console.print(f"  [red]✗ Failed to create {filename}: {e}[/red]")
            return False
    
    def generate_csv_report(self, templates_to_generate: List[Tuple[Template, str]], 
                           output_file: Optional[str] = None) -> Optional[str]:
        """Generate a CSV report of discovered templates"""
        if not output_file:
            timestamp = datetime.now().strftime('%Y-%m-%d_%H%M')
            output_file = self.review_dir / 'reports' / f'discovery_{timestamp}.csv'
        else:
            output_file = Path(output_file)
        
        # Ensure directory exists
        output_file.parent.mkdir(parents=True, exist_ok=True)
        
        # Prepare CSV data
        rows = []
        for template, action in templates_to_generate:
            best_match, score = self.matcher.find_best_match(template.name, self.local_rules)
            
            row = {
                'template_id': template.id,
                'template_name': template.name,
                'vendor': ','.join(template.vendors),
                'severity': template.severity,
                'action': action,
                'best_match': best_match['name'] if best_match else '',
                'match_score': f'{score:.1f}%',
                'created_date': template.created_timestamp,
                'modified_date': template.modified_timestamp or '',
                'mitre_tactics': ','.join(template.mitre_tactics),
                'yaml_file': self.generate_filename(
                    template.name, 
                    "(updated)" if action == 'updated' else ""
                )
            }
            rows.append(row)
        
        # Write CSV
        if not self.dry_run:
            with open(output_file, 'w', newline='') as f:
                if rows:
                    writer = csv.DictWriter(f, fieldnames=rows[0].keys())
                    writer.writeheader()
                    writer.writerows(rows)
            
            return str(output_file)
        
        return None
    
    def run(self, **filters):
        """Main discovery workflow"""
        self.console.print(Panel.fit(
            "[bold cyan]🔍 CrowdStrike Template Discovery[/bold cyan]",
            border_style="cyan"
        ))
        
        # Fetch and parse templates
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=self.console
        ) as progress:
            # Build FQL filter from run parameters (vendor + days_back are API-filterable)
            fql_filter = self._build_fql_filter(
                vendor=filters.get('vendor'),
                days_back=filters.get('days_back')
            )

            # Fetch templates — API first, local CSV fallback
            task = progress.add_task("Fetching templates from CRT API...", total=None)
            try:
                if fql_filter:
                    self.console.print(f"  [dim]FQL filter: {fql_filter}[/dim]")
                self.templates = self.fetch_from_api(fql_filter=fql_filter)
                progress.update(task, completed=True)
            except Exception as e:
                logger.warning(f"CRT API fetch failed ({e}), falling back to local CSV")
                self.console.print(f"[yellow]⚠ API unavailable — using local CSV fallback[/yellow]")
                progress.update(task, completed=True)
                local_csv = self.project_root / 'docs' / 'ngsiem_correlation_rule_templates.csv'
                if not local_csv.exists():
                    raise RuntimeError(
                        f"CRT API failed and no local CSV fallback found at {local_csv}. "
                        "Please provide docs/ngsiem_correlation_rule_templates.csv."
                    ) from e
                self.templates = self.parse_csv_data(local_csv.read_text())

            self.stats['total_templates'] = len(self.templates)
            self.console.print(f"✓ Found [green]{len(self.templates)}[/green] templates")
            
            # Load local rules
            task = progress.add_task("Loading local rules...", total=None)
            self.local_rules = self.load_local_rules()
            progress.update(task, completed=True)
            self.console.print(f"✓ Found [green]{len(self.local_rules)}[/green] rules in {self.rules_dir.relative_to(self.project_root)}")
            
            # Load manifest
            task = progress.add_task("Loading manifest...", total=None)
            self.manifest = self.load_manifest()
            progress.update(task, completed=True)

            # Load deployed state
            task = progress.add_task("Loading deployed state...", total=None)
            self.deployed_state = self.load_deployed_state()
            progress.update(task, completed=True)
            self.console.print(f"✓ Found [green]{len(self.deployed_state)}[/green] deployed detections in state file")
        
        # Apply filters
        self.console.print("\n[yellow]Applying filters:[/yellow]")
        # Separate filter arguments from other options
        filter_args = {k: v for k, v in filters.items() 
                      if k in ['vendor', 'severity', 'days_back', 'mitre_tactic', 'mitre_technique']}
        filtered_templates = self.apply_filters(self.templates, **filter_args)
        
        # Display filter summary
        filter_summary = []
        if filters.get('vendor'):
            filter_summary.append(f"Vendor: {', '.join(filters['vendor'])}")
        if filters.get('severity'):
            filter_summary.append(f"Severity: {', '.join(filters['severity'])}")
        if filters.get('days_back'):
            filter_summary.append(f"Date range: last {filters['days_back']} days")
        if filters.get('mitre_tactic'):
            filter_summary.append(f"MITRE Tactic: {', '.join(filters['mitre_tactic'])}")
        if filters.get('mitre_technique'):
            filter_summary.append(f"MITRE Technique: {', '.join(filters['mitre_technique'])}")
        
        for item in filter_summary:
            self.console.print(f"  - {item}")
        
        if not filter_summary:
            self.console.print("  - No filters applied")
        
        self.console.print(f"\nFiltered to [cyan]{len(filtered_templates)}[/cyan] templates")
        
        # Analyze templates
        self.console.print("\n[yellow]Analyzing templates...[/yellow]")
        templates_to_generate = []
        
        with Progress(console=self.console) as progress:
            task = progress.add_task("Processing templates...", total=len(filtered_templates))
            
            for template in filtered_templates:
                action = self.process_template(template)
                if action and action != 'skipped':
                    templates_to_generate.append((template, action))
                progress.update(task, advance=1)
        
        # Apply automation filters
        if filters.get('max_new_templates') and len(templates_to_generate) > filters['max_new_templates']:
            # Prioritize templates by severity (high/critical first)
            templates_to_generate.sort(key=lambda x: (
                x[0].severity_numeric if hasattr(x[0], 'severity_numeric') else 50
            ), reverse=True)
            original_count = len(templates_to_generate)
            templates_to_generate = templates_to_generate[:filters['max_new_templates']]
            self.console.print(f"[yellow]Limited to {filters['max_new_templates']} templates (was {original_count})[/yellow]")
        
        if filters.get('priority_filter'):
            priority_severities = {
                'critical': [90, 100],
                'high': [70, 80, 90, 100], 
                'medium': [50, 60, 70, 80, 90, 100],
                'low': [30, 40, 50, 60, 70, 80, 90, 100],
                'info': [10, 20, 30, 40, 50, 60, 70, 80, 90, 100]
            }
            allowed_severities = set()
            for priority in filters['priority_filter']:
                if priority.lower() in priority_severities:
                    allowed_severities.update(priority_severities[priority.lower()])
            
            if allowed_severities:
                original_count = len(templates_to_generate)
                templates_to_generate = [
                    (template, action) for template, action in templates_to_generate
                    if getattr(template, 'severity_numeric', 50) in allowed_severities
                ]
                self.console.print(f"[yellow]Priority filter applied: {len(templates_to_generate)} of {original_count} templates match[/yellow]")
        
        if filters.get('exclude_experimental'):
            original_count = len(templates_to_generate)
            templates_to_generate = [
                (template, action) for template, action in templates_to_generate
                if not any(keyword in template.name.lower() 
                         for keyword in ['experimental', 'beta', 'test', 'poc'])
            ]
            self.console.print(f"[yellow]Excluded experimental: {len(templates_to_generate)} of {original_count} templates remaining[/yellow]")
        
        # Display statistics
        self.console.print("\n[bold]Analysis Results:[/bold]")
        self.console.print(f"  🎯 Matched: {self.stats['matched']} templates (>{self.match_threshold}% confidence)")
        self.console.print(f"  🆕 New: {self.stats['new']} templates")
        self.console.print(f"  🔄 Updated: {self.stats['updated']} templates")
        self.console.print(f"  ⏭️  Skipped: {self.stats['skipped']} templates (already generated, no changes)")
        
        # Generate templates
        if templates_to_generate:
            self.console.print(f"\n[yellow]Generating {len(templates_to_generate)} templates...[/yellow]")

            for template, action in templates_to_generate:
                self.generate_template_file(template, action)

            # Save manifest
            if not self.dry_run:
                self.save_manifest()
        else:
            self.console.print("\n[green]No new or updated templates to generate![/green]")

        # Generate CSV report if requested
        csv_file = None
        if filters.get('output_csv') and templates_to_generate:
            csv_path = Path(filters.get('output_csv'))
            if not csv_path.is_absolute():
                csv_path = self.project_root / csv_path
            csv_file = self.generate_csv_report(templates_to_generate, str(csv_path))

        # Handle auto-review mode
        if filters.get('auto_review') and not self.dry_run and templates_to_generate:
            self.console.print(f"\n[yellow]Auto-review mode: Moving templates to templates_review/ directory[/yellow]")
            # Move generated templates to templates_review instead of manual review
            # This is handled by changing the output directory earlier in the process

        # Generate output based on format
        if filters.get('output_format') == 'json':
            # JSON output for automation
            result = {
                'timestamp': datetime.now().isoformat(),
                'summary': {
                    'total_templates_found': len(filtered_templates),
                    'new_templates': sum(1 for _, a in templates_to_generate if a == 'new'),
                    'updated_templates': sum(1 for _, a in templates_to_generate if a == 'updated'),
                    'total_generated': self.stats['generated'],
                    'dry_run': self.dry_run
                },
                'templates': [
                    {
                        'name': template.name,
                        'id': template.id,
                        'severity': template.severity,
                        'action': action,
                        'vendors': template.vendors,
                        'mitre_attack': template.mitre_attack
                    }
                    for template, action in templates_to_generate
                ],
                'filters_applied': {
                    'max_new_templates': filters.get('max_new_templates'),
                    'priority_filter': filters.get('priority_filter'),
                    'exclude_experimental': filters.get('exclude_experimental'),
                    'auto_review': filters.get('auto_review')
                }
            }
            print(json.dumps(result, indent=2))
        else:
            # Console output (default)
            self.console.print("\n" + "="*60)
            self.console.print("[bold green]Summary:[/bold green]")
            self.console.print(f"  - New templates generated: {sum(1 for _, a in templates_to_generate if a == 'new')}")
            self.console.print(f"  - Updated templates generated: {sum(1 for _, a in templates_to_generate if a == 'updated')}")
            self.console.print(f"  - Total files created: {self.stats['generated']}")

            if not self.dry_run:
                output_dir = "templates_review" if filters.get('auto_review') else self.review_dir.relative_to(self.project_root)
                self.console.print(f"  - Output directory: {output_dir}/")
                if csv_file:
                    self.console.print(f"  - Report saved: {Path(csv_file).relative_to(self.project_root)}")

            if not filters.get('auto_review'):
                self.console.print(f"\n[cyan]Review templates in {self.review_dir.relative_to(self.project_root)}/ before moving to rules/[/cyan]")
            else:
                self.console.print(f"\n[cyan]Templates automatically placed in templates_review/ for PR workflow[/cyan]")


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description='Discover CrowdStrike templates not yet in IaC',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --vendor aws --severity high,critical
  %(prog)s --vendor microsoft --days-back 30
  %(prog)s --vendor all --mitre-tactic TA0003
  %(prog)s --vendor crowdstrike --output-csv report.csv --dry-run
        """
    )
    
    # Filter arguments
    parser.add_argument('--vendor', nargs='+', 
                       help='Filter by vendor (aws, microsoft, google, crowdstrike, generic, all)')
    parser.add_argument('--severity', type=lambda s: s.split(','),
                       help='Filter by severity (info,low,medium,high,critical)')
    parser.add_argument('--days-back', type=int,
                       help='Only templates created/modified in last N days')
    parser.add_argument('--mitre-tactic', nargs='+',
                       help='Filter by MITRE ATT&CK tactic (e.g., TA0003)')
    parser.add_argument('--mitre-technique', nargs='+',
                       help='Filter by MITRE ATT&CK technique (e.g., T1078)')
    
    # Options
    parser.add_argument('--threshold', type=float, default=80.0,
                       help='Match threshold percentage (default: 80)')
    parser.add_argument('--output-csv', 
                       help='Generate CSV report to specified file')
    parser.add_argument('--dry-run', action='store_true',
                       help='Preview what would be generated without creating files')
    parser.add_argument('--verbose', action='store_true',
                       help='Enable verbose logging')
    
    # Automation options
    parser.add_argument('--auto-review', action='store_true',
                       help='Automatically place templates in templates_review/ directory')
    parser.add_argument('--max-new-templates', type=int, default=100,
                       help='Maximum new templates to process per run (default: 100)')
    parser.add_argument('--priority-filter', 
                       help='Comma-separated priority levels to include (high,critical)')
    parser.add_argument('--exclude-experimental', action='store_true',
                       help='Skip experimental or beta templates')
    parser.add_argument('--output-format', choices=['console', 'json'], default='console',
                       help='Output format for automation (default: console)')
    
    args = parser.parse_args()
    
    # Configure logging
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Prepare filters
    filters = {}
    if args.vendor:
        filters['vendor'] = args.vendor
    if args.severity:
        filters['severity'] = args.severity
    if args.days_back:
        filters['days_back'] = args.days_back
    if args.mitre_tactic:
        filters['mitre_tactic'] = args.mitre_tactic
    if args.mitre_technique:
        filters['mitre_technique'] = args.mitre_technique
    if args.output_csv:
        filters['output_csv'] = args.output_csv
    
    # Automation filters
    if args.auto_review:
        filters['auto_review'] = args.auto_review
    if args.max_new_templates:
        filters['max_new_templates'] = args.max_new_templates
    if args.priority_filter:
        filters['priority_filter'] = args.priority_filter.split(',')
    if args.exclude_experimental:
        filters['exclude_experimental'] = args.exclude_experimental
    if args.output_format:
        filters['output_format'] = args.output_format
    
    # Run discovery
    try:
        discovery = TemplateDiscovery(
            match_threshold=args.threshold,
            dry_run=args.dry_run,
            output_format=filters.get('output_format', 'console')
        )
        discovery.run(**filters)
    except KeyboardInterrupt:
        if filters.get('output_format') != 'json':
            console.print("\n[yellow]Discovery cancelled by user[/yellow]")
        sys.exit(1)
    except Exception as e:
        if filters.get('output_format') == 'json':
            # For JSON mode, print error to stderr to avoid corrupting stdout
            import sys
            print(f"Error: {e}", file=sys.stderr)
        else:
            console.print(f"\n[red]Error: {e}[/red]")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)


if __name__ == '__main__':
    main()