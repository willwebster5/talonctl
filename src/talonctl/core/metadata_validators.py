"""Shared metadata-block validators used by every provider's validate_template.

This module owns the universal metadata.maturity schema. Per-resource-type
validators (e.g. metadata.ads for detections) live in the provider that owns
that namespace — they are not shared here.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List

_DATE_PATTERN = re.compile(r"^\d{4}-\d{2}-\d{2}$")

MATURITY_ALLOWED_FIELDS = frozenset({"created", "last_tuned", "tune_count", "confidence"})
MATURITY_DATE_FIELDS = frozenset({"created", "last_tuned"})
MATURITY_CONFIDENCE_VALUES = frozenset({"low", "medium", "high", "validated"})


def validate_maturity(template: Dict[str, Any]) -> List[str]:
    """Validate `template["metadata"]["maturity"]` if present. Return error list.

    Empty list when the block is absent or valid. All four maturity fields are
    optional when the maturity block itself is present. Errors accumulate — this
    function does NOT short-circuit.
    """
    errors: List[str] = []
    metadata = template.get("metadata")
    if metadata is None:
        return errors

    if not isinstance(metadata, dict):
        errors.append("'metadata' must be a dictionary")
        return errors

    maturity = metadata.get("maturity")
    if maturity is None:
        return errors

    if not isinstance(maturity, dict):
        errors.append("'metadata.maturity' must be a dictionary")
        return errors

    unknown = set(maturity.keys()) - MATURITY_ALLOWED_FIELDS
    if unknown:
        known = ", ".join(sorted(MATURITY_ALLOWED_FIELDS))
        errors.append(f"Unknown metadata.maturity key(s): {', '.join(sorted(unknown))}. Known keys: {known}")

    for field in MATURITY_DATE_FIELDS:
        if field not in maturity:
            continue
        val = maturity[field]
        if field == "last_tuned" and val is None:
            continue
        if not isinstance(val, str) or not _DATE_PATTERN.match(val):
            suffix = " or null" if field == "last_tuned" else ""
            errors.append(f"metadata.maturity.{field} must be YYYY-MM-DD date{suffix} (got {val!r})")

    if "tune_count" in maturity:
        val = maturity["tune_count"]
        # bool is a subclass of int — reject it explicitly.
        if isinstance(val, bool) or not isinstance(val, int) or val < 0:
            errors.append(f"metadata.maturity.tune_count must be a non-negative integer (got {val!r})")

    if "confidence" in maturity:
        val = maturity["confidence"]
        if val not in MATURITY_CONFIDENCE_VALUES:
            allowed = ", ".join(["low", "medium", "high", "validated"])
            errors.append(f"metadata.maturity.confidence must be one of: {allowed} (got {val!r})")

    return errors
