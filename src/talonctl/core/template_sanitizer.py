"""Shared template-sanitization helpers.

Every provider's API-payload prep and content-hash path calls into this module
as its FIRST step. Provider-specific stripping/transforms (e.g. dashboard's
tags->labels rename, or a provider deciding `description` is IaC-only for its
resource type) run AFTER this helper.

Adding a new universally-IaC top-level field → update RESERVED_TOP_LEVEL_FIELDS
here, once. Adding a new internal field → use the `_` prefix convention, no
code change. Adding a provider-specific IaC-only field (like dashboard's
stripping of `description`) → keep that logic in the provider, not here.
"""

from __future__ import annotations

from typing import Any, Dict

# Single source of truth for "what is universally IaC-only across ALL providers."
# A field belongs here only if there is no provider where it is an API field.
# Fields like `description` and `tags` are intentionally NOT in this set because
# they are API fields on detection/saved_search but not on dashboard — providers
# handle them per-type.
RESERVED_TOP_LEVEL_FIELDS = frozenset(
    {
        "resource_id",
        "type",
        "dependencies",
        "metadata",
    }
)


def strip_for_api(template: Dict[str, Any]) -> Dict[str, Any]:
    """Return a shallow-copied dict with universally-IaC, internal, and metadata
    fields removed.

    This is the FIRST step of every provider's payload prep. Providers then apply
    their own provider-specific stripping and transforms on the returned dict.
    Callers that need to mutate sub-dicts (e.g. widget UUID normalization in
    dashboards) should apply their own copy.deepcopy AFTER calling this helper.
    """
    return {k: v for k, v in template.items() if not k.startswith("_") and k not in RESERVED_TOP_LEVEL_FIELDS}


def strip_for_hash(template: Dict[str, Any]) -> Dict[str, Any]:
    """Identical rules to strip_for_api — but named separately so callers can
    reason about intent (deploy payload vs. content-hash input) without coupling.
    If the two rules ever diverge, they diverge here, not across seven providers.
    """
    return strip_for_api(template)
