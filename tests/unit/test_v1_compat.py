import pytest
from talonctl.core.v1_compat import v1_to_v2
from talonctl.core.envelope import Envelope


def test_identity_lift_and_search_domain():
    env = v1_to_v2(
        {
            "resource_id": "ex___susp",
            "name": "Ex Susp",
            "_search_domain": "example_source",
            "tags": ["a", "b"],
            "severity": 70,
        },
        resource_type="detection",
    )
    assert isinstance(env, Envelope)
    assert env.kind == "Detection"
    assert env.metadata["resource_id"] == "ex___susp"
    assert env.metadata["name"] == "Ex Susp"
    assert env.spec["search_domain"] == "example_source"
    assert env.metadata["tags"] == ["a", "b"]
    assert "severity" in env.spec
    for k in ("resource_id", "name", "_search_domain", "tags"):
        assert k not in env.spec


def test_status_active_stays_string_in_spec():
    env = v1_to_v2({"resource_id": "r", "name": "n", "status": "active"}, resource_type="detection")
    assert env.spec["status"] == "active"
    assert "enabled" not in env.spec


def test_status_inactive_stays_string_in_spec():
    env = v1_to_v2({"resource_id": "r", "name": "n", "status": "inactive"}, resource_type="detection")
    assert env.spec["status"] == "inactive"
    assert "enabled" not in env.spec


def test_dependencies_renamed_to_depends_on():
    env = v1_to_v2(
        {"resource_id": "r", "name": "n", "dependencies": ["lookup_file.x"]},
        resource_type="detection",
    )
    assert env.spec["depends_on"] == ["lookup_file.x"]
    assert "dependencies" not in env.spec


def test_querystring_renamed_to_snake_case():
    env = v1_to_v2(
        {"resource_id": "r", "name": "n", "queryString": "| head 1"},
        resource_type="saved_search",
    )
    assert env.spec["query_string"] == "| head 1"
    assert "queryString" not in env.spec


def test_rule_id_dropped_but_schema_kept_in_spec():
    env = v1_to_v2(
        {"resource_id": "r", "name": "n", "rule_id": "abc", "$schema": "x", "severity": 1},
        resource_type="detection",
    )
    assert "rule_id" not in env.spec
    assert env.spec["$schema"] == "x"


def test_nested_v1_metadata_block_goes_to_envelope_metadata():
    env = v1_to_v2(
        {"resource_id": "r", "name": "n", "metadata": {"maturity": "production", "ads": {"x": 1}}},
        resource_type="detection",
    )
    assert env.metadata["maturity"] == "production"
    assert env.metadata["ads"] == {"x": 1}
    assert "metadata" not in env.spec


def test_v1_metadata_block_routes_to_envelope_metadata():
    flat = {
        "resource_id": "r",
        "name": "R",
        "severity": 10,
        "status": "active",
        "metadata": {"maturity": "production"},
    }
    env = v1_to_v2(flat, resource_type="detection")
    assert env.metadata["maturity"] == "production"
    assert "metadata" not in env.spec


def test_v1_metadata_block_does_not_clobber_identity():
    env = v1_to_v2(
        {
            "resource_id": "r",
            "name": "n",
            "tags": ["keep"],
            "metadata": {"resource_id": "evil", "name": "evil", "tags": ["nope"]},
        },
        resource_type="detection",
    )
    assert env.metadata["resource_id"] == "r"
    assert env.metadata["name"] == "n"
    assert env.metadata["tags"] == ["keep"]


def test_rtr_script_resource_id_minted_from_name():
    env = v1_to_v2({"name": "List Service"}, resource_type="rtr_script")
    assert env.kind == "RtrScript"
    assert env.metadata["resource_id"]
    assert " " not in env.metadata["resource_id"]
    assert env.metadata["name"] == "List Service"


def test_existing_resource_id_preferred_over_minting():
    env = v1_to_v2({"resource_id": "sysmon_config", "name": "sysmonconfig.xml"}, resource_type="rtr_put_file")
    assert env.metadata["resource_id"] == "sysmon_config"


def test_missing_resource_id_for_non_rtr_kind_raises():
    with pytest.raises(ValueError, match="resource_id"):
        v1_to_v2({"name": "no id"}, resource_type="detection")
