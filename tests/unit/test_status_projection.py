from talonctl.core.state_manager import ResourceState
from talonctl.core.status_projection import project_status


def _rs(type, id="", provider_metadata=None, deployed_at="2026-01-01T00:00:00+00:00", content_hash="hash123"):
    return ResourceState(
        type=type,
        id=id,
        content_hash=content_hash,
        template_path="resources/x.yaml",
        deployed_at=deployed_at,
        last_modified="2026-01-01T00:00:00+00:00",
        provider_metadata=provider_metadata or {},
        dependencies=[],
    )


def test_detection_rule_id_from_provider_metadata():
    rs = _rs("detection", id="UUID1", provider_metadata={"rule_id": "UUID1"})
    status = project_status(rs)
    assert status["server_id"] == "UUID1"
    assert status["rule_id"] == "UUID1"


def test_detection_rule_id_falls_back_to_top_level_id():
    # older entry: provider_metadata has no rule_id, UUID lives in `id`
    rs = _rs("detection", id="UUID2", provider_metadata={"description": "..."})
    status = project_status(rs)
    assert status["server_id"] == "UUID2"
    assert status["rule_id"] == "UUID2"


def test_synthetic_placeholder_id_yields_no_server_id():
    # never-deployed: id is "<type>.<resource_id>"
    rs = _rs("saved_search", id="saved_search.example_source_enrich")
    status = project_status(rs)
    assert "server_id" not in status


def test_synthetic_placeholder_detection_yields_no_rule_id():
    rs = _rs("detection", id="detection.example_source___x", provider_metadata={})
    status = project_status(rs)
    assert "server_id" not in status
    assert "rule_id" not in status


def test_non_detection_id_passes_through_as_server_id():
    rs = _rs("lookup_file", id="approved_uploaders.csv")
    status = project_status(rs)
    assert status["server_id"] == "approved_uploaders.csv"
    assert "rule_id" not in status  # rule_id is detection-only


def test_missing_deployed_at_and_hash_are_omitted():
    rs = _rs("dashboard", id="DASH1", deployed_at="", content_hash="")
    status = project_status(rs)
    assert status["server_id"] == "DASH1"
    assert "deployed_at" not in status
    assert "content_hash" not in status


def test_deployed_at_and_hash_present_when_set():
    rs = _rs("workflow", id="WF1", deployed_at="2026-02-02T00:00:00+00:00", content_hash="wfhash")
    status = project_status(rs)
    assert status["deployed_at"] == "2026-02-02T00:00:00+00:00"
    assert status["content_hash"] == "wfhash"
