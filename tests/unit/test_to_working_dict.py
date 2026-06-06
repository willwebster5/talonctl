from talonctl.core.v1_compat import v1_to_v2

# Per-type v1 flat fixtures (minimal but covering the renamed/identity keys).
V1_DETECTION = {
    "resource_id": "aws_root_login",
    "name": "AWS Root Login",
    "type": "behavioral",
    "description": "root login",
    "severity": 80,
    "status": "active",
    "tags": ["aws", "auth"],
    "search": {"filter": "x", "lookback": 60},
    "dependencies": ["lookup_file.trusted_ips"],
}
V1_SAVED_SEARCH = {
    "resource_id": "enrich",
    "name": "Enrich",
    "$schema": "https://schemas.humio.com/query/v0.6.0",
    "queryString": "head()",
    "_search_domain": "all",
    "labels": {"team": "soc"},
}


def test_detection_round_trips_provider_keys():
    env = v1_to_v2(V1_DETECTION, resource_type="detection")
    working = env.to_working_dict()
    assert working["status"] == "active"
    assert working["tags"] == ["aws", "auth"]
    assert working["name"] == "AWS Root Login"
    assert working["resource_id"] == "aws_root_login"
    assert working["type"] == "behavioral"
    assert working["search"] == {"filter": "x", "lookback": 60}
    assert working["dependencies"] == ["lookup_file.trusted_ips"]


def test_saved_search_renames_back_to_legacy_keys():
    env = v1_to_v2(V1_SAVED_SEARCH, resource_type="saved_search")
    working = env.to_working_dict()
    assert working["queryString"] == "head()"  # query_string -> queryString
    assert working["_search_domain"] == "all"  # search_domain -> _search_domain
    assert working["$schema"].startswith("https://")  # $schema preserved (not dropped)
    assert working["labels"] == {"team": "soc"}


def test_working_dict_is_isolated_from_envelope():
    env = v1_to_v2(V1_DETECTION, resource_type="detection")
    w = env.to_working_dict()
    w["search"]["filter"] = "MUTATED"
    w["tags"].append("MUTATED")
    assert env.spec["search"]["filter"] == "x"  # envelope untouched
    assert env.metadata["tags"] == ["aws", "auth"]  # envelope untouched


def test_full_round_trip_equality_with_metadata_block():
    flat = {
        "resource_id": "r",
        "name": "R",
        "type": "behavioral",
        "description": "d",
        "severity": 70,
        "status": "active",
        "tags": ["a", "b"],
        "labels": {"team": "soc"},
        "search": {"filter": "x", "lookback": 60},
        "metadata": {"maturity": "production", "ads": {"k": "v"}},
    }
    env = v1_to_v2(flat, resource_type="detection")
    assert env.to_working_dict() == flat  # exact: no renamed keys in this fixture


def test_origin_path_becomes_template_path():
    env = v1_to_v2(V1_DETECTION, resource_type="detection")
    env.origin_path = "/proj/resources/detections/x.yaml"
    assert env.to_working_dict()["_template_path"] == "/proj/resources/detections/x.yaml"
    env.origin_path = None
    assert "_template_path" not in env.to_working_dict()
