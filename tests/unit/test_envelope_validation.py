from talonctl.core.envelope import Envelope
from talonctl.core.envelope_validation import (
    validate_authored_envelope,
    check_depends_on_cycles,
    check_whitespace_hygiene,
)


def _det(rid, depends_on=None):
    spec = {"severity": 1}
    if depends_on is not None:
        spec["depends_on"] = depends_on
    return Envelope("talon/v2", "Detection", {"resource_id": rid}, spec)


def test_valid_envelope_has_no_errors():
    assert validate_authored_envelope(_det("d1")) == []


def test_missing_resource_id_is_an_error():
    env = Envelope("talon/v2", "Detection", {}, {"severity": 1})
    errs = validate_authored_envelope(env)
    assert any("resource_id" in e for e in errs)


def test_empty_spec_is_an_error():
    env = Envelope("talon/v2", "Detection", {"resource_id": "d1"}, {})
    assert validate_authored_envelope(env) != []


def test_extra_metadata_keys_allowed():
    # metadata is talonctl-internal and open by design: the v1 `metadata:` block
    # (maturity, ads, custom frameworks, ...) is routed here, so arbitrary keys
    # must validate. Identity constraints (resource_id) are still enforced.
    env = Envelope("talon/v2", "Detection", {"resource_id": "d1", "maturity": "production"}, {"severity": 1})
    assert validate_authored_envelope(env) == []


def test_no_cycle_returns_empty():
    a = _det("a", ["detection.b"])
    b = _det("b")
    assert check_depends_on_cycles([a, b]) == []


def test_cycle_detected():
    a = _det("a", ["detection.b"])
    b = _det("b", ["detection.a"])
    errs = check_depends_on_cycles([a, b])
    assert errs and any("cycle" in e.lower() for e in errs)


def test_external_ref_is_not_a_cycle():
    # A ref to a resource not in this set (cross-file / v1 / filtered run) is
    # NOT a cycle — spec §7 expects cross-file refs to resolve elsewhere.
    a = _det("a", ["lookup_file.defined_in_another_file"])
    assert check_depends_on_cycles([a]) == []


def test_duplicate_depends_on_is_not_a_cycle():
    # A ref listed twice is one logical edge, not a cycle (regression).
    a = _det("a", ["detection.b", "detection.b"])
    b = _det("b")
    assert check_depends_on_cycles([a, b]) == []


def _ss(query):
    return Envelope("talon/v2", "SavedSearch", {"resource_id": "s1"}, {"query_string": query, "search_domain": "all"})


def test_whitespace_hygiene_passes_clean_multiline():
    assert check_whitespace_hygiene(_ss("#x\n| head()\n| count()\n")) == []


def test_whitespace_hygiene_flags_trailing_whitespace():
    errs = check_whitespace_hygiene(_ss("#x   \n| head()\n"))
    assert errs and any("trailing whitespace" in e and "query_string" in e for e in errs)


def test_whitespace_hygiene_flags_tab():
    errs = check_whitespace_hygiene(_ss("#x\n| groupBy([a], function=([\n\tcount()\n]))\n"))
    assert errs and any("tab" in e.lower() and "query_string" in e for e in errs)


def test_whitespace_hygiene_checks_metadata_and_nested():
    # nested spec values (e.g. dashboard widget queries) and a single-line value
    # with no newline are not block scalars, so they're not flagged.
    env = Envelope("talon/v2", "Dashboard", {"resource_id": "d"},
                   {"widgets": {"w1": {"queryString": "#a\n| b  \n"}}})
    errs = check_whitespace_hygiene(env)
    assert any("trailing whitespace" in e and "widgets.w1.queryString" in e for e in errs)
