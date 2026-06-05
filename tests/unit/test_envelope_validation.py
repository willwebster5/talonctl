from talonctl.core.envelope import Envelope
from talonctl.core.envelope_validation import validate_authored_envelope, check_depends_on_cycles


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


def test_unknown_metadata_key_rejected():
    env = Envelope("talon/v2", "Detection", {"resource_id": "d1", "bogus": 1}, {"severity": 1})
    assert validate_authored_envelope(env) != []


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
