"""Extract CQL query references from discovered templates.

Each query-bearing resource type exposes its CQL in different fields. This
module centralises that knowledge so callers (validate --queries, future
refactors of the plan-path validator) can iterate queries uniformly without
embedding per-type field names.
"""

from dataclasses import dataclass
from typing import Dict, List

from talonctl.core.template_discovery import DiscoveredTemplate


@dataclass
class QueryRef:
    resource_type: str
    resource_id: str
    resource_name: str
    query: str
    location: str
    query_snippet: str


def collect_queries_from_templates(
    templates_by_type: Dict[str, List[DiscoveredTemplate]],
) -> List[QueryRef]:
    return []
