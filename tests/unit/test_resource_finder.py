"""Unit tests for ResourceFinder (pure, no I/O)."""

from dataclasses import asdict

from talonctl.core.resource_finder import (
    FindOutput,
    FindResult,
    NON_IAC_PREFIXES,
    NonIacInfo,
    RULE_ID_RE,
    ResourceFinder,
)


class TestResourceFinderScaffold:
    """Smoke tests that the module exports and basic shapes exist."""

    def test_rule_id_regex_matches_32_hex_lowercase(self):
        assert RULE_ID_RE.fullmatch("c1d430691e8b42e7b336956f6a3af6fc")

    def test_rule_id_regex_matches_32_hex_uppercase(self):
        assert RULE_ID_RE.fullmatch("C1D430691E8B42E7B336956F6A3AF6FC")

    def test_rule_id_regex_rejects_non_hex(self):
        assert RULE_ID_RE.fullmatch("c1d430691e8b42e7b336956f6a3af6fz") is None

    def test_rule_id_regex_rejects_wrong_length(self):
        assert RULE_ID_RE.fullmatch("c1d430691e8b42e7") is None

    def test_non_iac_prefixes_has_fcs_thirdparty_cwpp(self):
        assert set(NON_IAC_PREFIXES.keys()) == {"fcs", "thirdparty", "cwpp"}
        for prefix, info in NON_IAC_PREFIXES.items():
            assert isinstance(info, NonIacInfo)
            assert info.prefix == prefix
            assert info.label
            assert info.tuning_location
            assert info.tip

    def test_find_output_is_json_serializable(self):
        out = FindOutput(query="x", strategy_used="none", matches=[])
        d = asdict(out)
        assert d == {
            "query": "x",
            "strategy_used": "none",
            "matches": [],
            "non_iac_info": None,
        }

    def test_find_result_has_expected_fields(self):
        r = FindResult(
            resource_type="detection",
            resource_id="aws_root_login",
            display_name="AWS - Root Login",
            rule_id="c1d430691e8b42e7b336956f6a3af6fc",
            status="active",
            severity=70,
            template_path="resources/detections/aws/aws_root_login.yaml",
            deployed_at="2026-03-14T19:22:03Z",
            dependencies=["saved_search.aws_service_accounts"],
            iac_tunable=True,
            deployed=True,
        )
        d = asdict(r)
        assert d["resource_id"] == "aws_root_login"
        assert d["iac_tunable"] is True
        assert d["deployed"] is True

    def test_resource_finder_instantiates_with_empty_state(self):
        finder = ResourceFinder({"version": "3.0", "resources": {}})
        out = finder.find("anything")
        assert isinstance(out, FindOutput)
        assert out.strategy_used == "none"
        assert out.matches == []


def _fixture_state():
    """Canonical minimal state dict used across strategy tests."""
    return {
        "version": "3.0",
        "resources": {
            "detection": {
                "aws_root_login": {
                    "type": "detection",
                    "id": "det-id-1",
                    "content_hash": "abc",
                    "template_path": "resources/detections/aws/aws_root_login.yaml",
                    "deployed_at": "2026-03-14T19:22:03Z",
                    "last_modified": "2026-03-14T19:22:03Z",
                    "provider_metadata": {
                        "rule_id": "c1d430691e8b42e7b336956f6a3af6fc",
                        "status": "active",
                        "severity": 70,
                    },
                    "dependencies": ["saved_search.aws_service_accounts"],
                    "display_name": "AWS - Root Login via Console",
                },
                "aws_user_login": {
                    "type": "detection",
                    "id": "det-id-2",
                    "content_hash": "def",
                    "template_path": "resources/detections/aws/aws_user_login.yaml",
                    "deployed_at": "2026-03-15T00:00:00Z",
                    "last_modified": "2026-03-15T00:00:00Z",
                    "provider_metadata": {
                        "rule_id": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                        "status": "active",
                        "severity": 40,
                    },
                    "dependencies": [],
                    "display_name": "AWS - User Login",
                },
            },
            "saved_search": {
                "aws_service_accounts": {
                    "type": "saved_search",
                    "id": "ss-id-1",
                    "content_hash": "ghi",
                    "template_path": "resources/saved_searches/aws_service_accounts.yaml",
                    "deployed_at": "2026-03-10T00:00:00Z",
                    "last_modified": "2026-03-10T00:00:00Z",
                    "provider_metadata": {},
                    "dependencies": [],
                    "display_name": "AWS Service Accounts",
                },
            },
        },
    }


class TestStrategyRuleId:
    def test_exact_rule_id_returns_single_match(self):
        finder = ResourceFinder(_fixture_state())
        out = finder.find("c1d430691e8b42e7b336956f6a3af6fc")
        assert out.strategy_used == "rule_id"
        assert len(out.matches) == 1
        m = out.matches[0]
        assert m.resource_type == "detection"
        assert m.resource_id == "aws_root_login"
        assert m.rule_id == "c1d430691e8b42e7b336956f6a3af6fc"
        assert m.status == "active"
        assert m.severity == 70
        assert m.iac_tunable is True
        assert m.deployed is True

    def test_rule_id_case_insensitive(self):
        finder = ResourceFinder(_fixture_state())
        out = finder.find("C1D430691E8B42E7B336956F6A3AF6FC")
        assert out.strategy_used == "rule_id"
        assert len(out.matches) == 1

    def test_rule_id_with_type_filter(self):
        finder = ResourceFinder(_fixture_state())
        out = finder.find("c1d430691e8b42e7b336956f6a3af6fc", resource_type="saved_search")
        # UUID looks like a rule_id but no match under saved_search -> fall through
        assert out.strategy_used != "rule_id"

    def test_rule_id_no_match_falls_through(self):
        finder = ResourceFinder(_fixture_state())
        out = finder.find("ffffffffffffffffffffffffffffffff")
        assert out.strategy_used == "none"
        assert out.matches == []

    def test_rule_id_tolerates_missing_provider_metadata(self):
        state = _fixture_state()
        state["resources"]["detection"]["aws_root_login"]["provider_metadata"] = None
        finder = ResourceFinder(state)
        out = finder.find("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
        assert out.strategy_used == "rule_id"
        assert len(out.matches) == 1
        assert out.matches[0].resource_id == "aws_user_login"


class TestStrategyResourceId:
    def test_exact_key_match(self):
        finder = ResourceFinder(_fixture_state())
        out = finder.find("aws_root_login")
        assert out.strategy_used == "resource_id"
        assert len(out.matches) == 1
        assert out.matches[0].resource_type == "detection"
        assert out.matches[0].resource_id == "aws_root_login"

    def test_type_dot_name_form(self):
        finder = ResourceFinder(_fixture_state())
        out = finder.find("saved_search.aws_service_accounts")
        assert out.strategy_used == "resource_id"
        assert len(out.matches) == 1
        assert out.matches[0].resource_type == "saved_search"

    def test_type_filter_narrows(self):
        finder = ResourceFinder(_fixture_state())
        out = finder.find("aws_root_login", resource_type="saved_search")
        assert out.strategy_used == "none"

    def test_same_key_across_types_returns_all(self):
        state = _fixture_state()
        # Create a saved_search with the same bare key as a detection
        state["resources"]["saved_search"]["aws_root_login"] = {
            "type": "saved_search",
            "id": "ss-id-2",
            "content_hash": "",
            "template_path": "resources/saved_searches/aws_root_login.yaml",
            "deployed_at": "",
            "last_modified": "",
            "provider_metadata": {},
            "dependencies": [],
            "display_name": "AWS Root Login (saved search)",
        }
        finder = ResourceFinder(state)
        out = finder.find("aws_root_login")
        assert out.strategy_used == "resource_id"
        assert len(out.matches) == 2
        # Sort is (resource_type, resource_id): detection before saved_search
        assert [m.resource_type for m in out.matches] == ["detection", "saved_search"]

    def test_missing_key_falls_through(self):
        finder = ResourceFinder(_fixture_state())
        out = finder.find("nonexistent_resource")
        assert out.strategy_used == "none"


class TestStrategyCompositeId:
    def test_ngsiem_prefix_delegates_to_rule_id(self):
        finder = ResourceFinder(_fixture_state())
        out = finder.find("ngsiem:c1d430691e8b42e7b336956f6a3af6fc")
        assert out.strategy_used == "composite_id_ngsiem"
        assert len(out.matches) == 1
        assert out.matches[0].resource_id == "aws_root_login"

    def test_ngsiem_prefix_with_unknown_uuid_returns_empty_match_set(self):
        finder = ResourceFinder(_fixture_state())
        out = finder.find("ngsiem:ffffffffffffffffffffffffffffffff")
        assert out.strategy_used == "composite_id_ngsiem"
        assert out.matches == []

    def test_fcs_prefix_returns_non_iac_info(self):
        finder = ResourceFinder(_fixture_state())
        out = finder.find("fcs:abc123")
        assert out.strategy_used == "composite_id_non_iac"
        assert out.matches == []
        assert out.non_iac_info is not None
        assert out.non_iac_info.prefix == "fcs"
        assert "Cloud Security" in out.non_iac_info.label

    def test_thirdparty_prefix_returns_non_iac_info(self):
        finder = ResourceFinder(_fixture_state())
        out = finder.find("thirdparty:xyz")
        assert out.strategy_used == "composite_id_non_iac"
        assert out.non_iac_info.prefix == "thirdparty"

    def test_cwpp_prefix_returns_non_iac_info(self):
        finder = ResourceFinder(_fixture_state())
        out = finder.find("cwpp:xyz")
        assert out.strategy_used == "composite_id_non_iac"
        assert out.non_iac_info.prefix == "cwpp"

    def test_unknown_prefix_falls_through(self):
        finder = ResourceFinder(_fixture_state())
        out = finder.find("unknownprefix:something")
        assert out.strategy_used == "none"

    def test_colon_in_resource_id_key_still_falls_through_to_later_strategies(self):
        # Edge case: a key that happens to contain a colon but isn't a
        # known prefix should NOT be treated as composite_id.
        state = _fixture_state()
        state["resources"]["detection"]["weird:key"] = {
            "type": "detection",
            "id": "det-id-weird",
            "content_hash": "",
            "template_path": "",
            "deployed_at": "",
            "last_modified": "",
            "provider_metadata": {},
            "dependencies": [],
            "display_name": "Weird",
        }
        finder = ResourceFinder(state)
        out = finder.find("weird:key")
        # "weird" is not a known non-IaC prefix -> fall through -> resource_id hits
        assert out.strategy_used == "resource_id"
        assert len(out.matches) == 1
