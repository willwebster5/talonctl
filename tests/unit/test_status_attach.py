from talonctl.core.envelope import Envelope
from talonctl.core.status_projection import attach_status


def _env(rid="r", kind="Detection"):
    return Envelope(api_version="talon/v2", kind=kind, metadata={"resource_id": rid}, spec={})


def test_real_id_kept_when_deployed():
    # A real server id that literally starts with "<type>." must NOT be dropped
    # when the resource is actually deployed (deployed_at present).
    env = _env(kind="LookupFile")
    attach_status(
        env, {"id": "lookup_file.csv", "deployed_at": "2026-06-01T00:00:00Z", "content_hash": "abc"}, "lookup_file"
    )
    assert env.status["server_id"] == "lookup_file.csv"


def test_placeholder_dropped_when_not_deployed():
    env = _env(kind="SavedSearch")
    attach_status(env, {"id": "saved_search.enrich", "deployed_at": None, "content_hash": ""}, "saved_search")
    assert "server_id" not in env.status


def test_none_entry_sets_status_none():
    env = _env()
    attach_status(env, None, "detection")
    assert env.status is None


def test_detection_projects_rule_id_and_fields():
    env = _env(rid="aws_root_login")
    attach_status(
        env,
        {
            "id": "uuid-123",
            "deployed_at": "2026-06-01T00:00:00Z",
            "content_hash": "h",
            "provider_metadata": {"rule_id": "uuid-123"},
        },
        "detection",
    )
    assert env.status["server_id"] == "uuid-123"
    assert env.status["rule_id"] == "uuid-123"
    assert env.status["deployed_at"] == "2026-06-01T00:00:00Z"
