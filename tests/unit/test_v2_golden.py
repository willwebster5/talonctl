from pathlib import Path
from talonctl.core.envelope_loader import load_envelopes
from talonctl.core.envelope_validation import validate_envelope, check_depends_on_cycles

FIXTURE = Path(__file__).parent.parent / "fixtures" / "v2" / "example_resources.yaml"


def test_example_module_loads_as_three_resources():
    envs = load_envelopes(FIXTURE)
    assert [e.kind for e in envs] == ["LookupFile", "SavedSearch", "Detection"]


def test_every_resource_validates():
    envs = load_envelopes(FIXTURE)
    for env in envs:
        assert validate_envelope(env) == [], env.resource_id


def test_no_dependency_cycle():
    envs = load_envelopes(FIXTURE)
    assert check_depends_on_cycles(envs) == []
