from talonctl.core.envelope import (
    Envelope,
    API_VERSION,
    KIND_TO_TYPE,
    TYPE_TO_KIND,
    VALID_KINDS,
)


def test_api_version_constant():
    assert API_VERSION == "talon/v2"


def test_kind_type_maps_are_inverses_and_cover_all_kinds():
    assert len(KIND_TO_TYPE) == 10
    assert TYPE_TO_KIND["rtr_script"] == "RtrScript"
    assert all(TYPE_TO_KIND[v] == k for k, v in KIND_TO_TYPE.items())
    assert VALID_KINDS == frozenset(KIND_TO_TYPE)


def test_envelope_derived_properties():
    env = Envelope(
        api_version="talon/v2",
        kind="Detection",
        metadata={"resource_id": "ex___susp_upload", "name": "Ex"},
        spec={"severity": 70},
    )
    assert env.resource_id == "ex___susp_upload"
    assert env.resource_type == "detection"
    assert env.ref == "detection.ex___susp_upload"
    assert env.status is None
