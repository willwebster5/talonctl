from typing import Optional

from talonctl.core.v1_compat import v1_to_v2
from talonctl.core.envelope import Envelope


def make_envelope(flat: dict, resource_type: str, origin_path: Optional[str] = None) -> Envelope:
    """Build an Envelope from a legacy v1 flat dict, the way the loader will."""
    env = v1_to_v2(flat, resource_type=resource_type)
    if origin_path:
        env.origin_path = origin_path
    return env
