from typing import Optional

from talonctl.core.v1_compat import v1_to_v2
from talonctl.core.envelope import Envelope


def make_envelope(flat: dict, resource_type: str, origin_path: Optional[str] = None) -> Envelope:
    """Build an Envelope from a legacy v1 flat dict, the way the loader will."""
    env = v1_to_v2(flat, resource_type=resource_type)
    if origin_path:
        env.origin_path = origin_path
    return env


# Resource types whose provider.validate_template / plan_* / apply_* already
# consume an Envelope (Section 3 provider flip). Grows as each provider is
# migrated; cross-cutting tests use this to pass the right input shape per
# provider. Detection is the worked example (Task 6); Task 7 adds the rest.
ENVELOPE_CONSUMING_TYPES = frozenset({"detection", "saved_search", "lookup_file", "dashboard", "workflow"})


def validate_input(flat: dict, resource_type: str, origin_path: Optional[str] = None):
    """Return the right argument shape for provider.validate_template based on
    whether that provider type has been flipped to consume an Envelope yet.

    Flipped providers get an Envelope; not-yet-flipped providers get the raw
    flat dict. Lets cross-cutting tests exercise all providers during the
    incremental Section 3 migration.
    """
    if resource_type in ENVELOPE_CONSUMING_TYPES:
        return make_envelope(flat, resource_type, origin_path=origin_path)
    return flat
