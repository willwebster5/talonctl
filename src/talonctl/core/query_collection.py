"""Extract CQL query references from discovered templates.

Each query-bearing resource type exposes its CQL in different fields. This
module centralises that knowledge so callers (validate --queries, future
refactors of the plan-path validator) can iterate queries uniformly without
embedding per-type field names.
"""

from dataclasses import dataclass
from typing import Callable, Dict, List, Tuple

from talonctl.core.template_discovery import DiscoveredTemplate


@dataclass
class QueryRef:
    resource_type: str
    resource_id: str
    resource_name: str
    query: str
    location: str
    query_snippet: str


def _make_snippet(query: str) -> str:
    collapsed = " ".join(query.split())
    if len(collapsed) > 100:
        return collapsed[:100] + "..."
    return collapsed


def _extract_detection(template: dict) -> List[Tuple[str, str]]:
    """Return list of (query, location) pairs. Detection has 0 or 1."""
    search = template.get("search") or {}
    for field in ("filter", "query"):
        value = search.get(field)
        if isinstance(value, str) and value.strip():
            return [(value, f"search.{field}")]
    return []


def _extract_saved_search(template: dict) -> List[Tuple[str, str]]:
    value = template.get("queryString")
    if isinstance(value, str) and value.strip():
        return [(value, "queryString")]
    return []


_EXTRACTORS: Dict[str, Callable[[dict], List[Tuple[str, str]]]] = {
    "detection": _extract_detection,
    "saved_search": _extract_saved_search,
}


def collect_queries_from_templates(
    templates_by_type: Dict[str, List[DiscoveredTemplate]],
) -> List[QueryRef]:
    refs: List[QueryRef] = []
    for resource_type, templates in templates_by_type.items():
        extractor = _EXTRACTORS.get(resource_type)
        if extractor is None:
            continue
        for template in templates:
            for query, location in extractor(template.template_data):
                refs.append(
                    QueryRef(
                        resource_type=resource_type,
                        resource_id=template.resource_id,
                        resource_name=template.name,
                        query=query,
                        location=location,
                        query_snippet=_make_snippet(query),
                    )
                )
    return refs
