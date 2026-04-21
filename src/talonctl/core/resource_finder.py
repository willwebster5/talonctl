"""
Resource Finder — resolve arbitrary identifiers to talonctl-managed resources.

Pure logic: takes a state dict (optionally plus discovered templates for
`--include-undeployed`) and returns a FindOutput. No I/O, no Click, no
credentials, no falcon client. Intended to be wrapped by
`talonctl.commands.find`.
"""

import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


RULE_ID_RE = re.compile(r"^[0-9a-f]{32}$", re.IGNORECASE)


@dataclass
class FindResult:
    resource_type: str
    resource_id: str
    display_name: str
    rule_id: Optional[str]
    status: Optional[str]
    severity: Optional[int]
    template_path: Optional[str]
    deployed_at: Optional[str]
    dependencies: List[str]
    iac_tunable: bool
    deployed: bool


@dataclass
class NonIacInfo:
    prefix: str
    label: str
    tuning_location: str
    tip: str


@dataclass
class FindOutput:
    query: str
    strategy_used: str
    matches: List[FindResult] = field(default_factory=list)
    non_iac_info: Optional[NonIacInfo] = None


NON_IAC_PREFIXES: Dict[str, NonIacInfo] = {
    "fcs": NonIacInfo(
        prefix="fcs",
        label="Cloud Security (FCS IoA)",
        tuning_location="Falcon Console > Cloud Security > IoA Policies",
        tip="FCS alerts are governed by IoA policies, not NGSIEM detection templates.",
    ),
    "thirdparty": NonIacInfo(
        prefix="thirdparty",
        label="Third-Party Integration",
        tuning_location="Falcon Console > Data Connectors > Third-Party Integrations",
        tip="Third-party alerts are emitted by external integrations; tune at the source.",
    ),
    "cwpp": NonIacInfo(
        prefix="cwpp",
        label="Cloud Workload Protection",
        tuning_location="Falcon Console > Cloud Security > Runtime Protection",
        tip="CWPP alerts are governed by runtime policies, not NGSIEM detection templates.",
    ),
}


class ResourceFinder:
    """
    Resolve an arbitrary identifier to one or more talonctl-managed resources.

    Strategy order (first non-empty wins): rule_id, resource_id, composite_id,
    name_substring, glob.
    """

    def __init__(self, state: Dict[str, Any], templates: Optional[List[Any]] = None):
        self._state = state or {}
        self._resources: Dict[str, Dict[str, Dict[str, Any]]] = self._state.get("resources", {}) or {}
        self._templates = templates or []

    def find(self, query: str, resource_type: Optional[str] = None) -> FindOutput:
        for strategy in (
            self._try_rule_id,
            self._try_resource_id,
            self._try_composite_id,
        ):
            result = strategy(query, resource_type)
            if result is not None:
                return result
        return FindOutput(query=query, strategy_used="none", matches=[])

    def _iter_types(self, resource_type: Optional[str]):
        if resource_type:
            if resource_type in self._resources:
                yield resource_type
            return
        yield from self._resources.keys()

    def _build_result(self, rtype: str, key: str, entry: Dict[str, Any]) -> FindResult:
        pm = entry.get("provider_metadata") or {}
        if not isinstance(pm, dict):
            pm = {}
        return FindResult(
            resource_type=rtype,
            resource_id=key,
            display_name=entry.get("display_name") or key,
            rule_id=pm.get("rule_id"),
            status=pm.get("status"),
            severity=pm.get("severity"),
            template_path=entry.get("template_path"),
            deployed_at=entry.get("deployed_at"),
            dependencies=list(entry.get("dependencies") or []),
            iac_tunable=True,
            deployed=True,
        )

    def _try_rule_id(self, query: str, resource_type: Optional[str]) -> Optional[FindOutput]:
        if not RULE_ID_RE.fullmatch(query):
            return None
        q = query.lower()
        matches: List[FindResult] = []
        for rtype in self._iter_types(resource_type):
            for key, entry in (self._resources.get(rtype) or {}).items():
                pm = entry.get("provider_metadata") or {}
                if not isinstance(pm, dict):
                    continue
                rid = pm.get("rule_id")
                if isinstance(rid, str) and rid.lower() == q:
                    matches.append(self._build_result(rtype, key, entry))
        if not matches:
            return None
        matches.sort(key=lambda m: (m.resource_type, m.resource_id))
        return FindOutput(query=query, strategy_used="rule_id", matches=matches)

    def _try_resource_id(self, query: str, resource_type: Optional[str]) -> Optional[FindOutput]:
        matches: List[FindResult] = []

        # Explicit type.name form
        if "." in query and not resource_type:
            rtype, _, name = query.partition(".")
            entry = (self._resources.get(rtype) or {}).get(name)
            if entry is not None:
                matches.append(self._build_result(rtype, name, entry))

        # Bare key lookup — scan each type bucket (constant-time per type)
        if not matches:
            for rtype in self._iter_types(resource_type):
                entry = (self._resources.get(rtype) or {}).get(query)
                if entry is not None:
                    matches.append(self._build_result(rtype, query, entry))

        if not matches:
            return None
        matches.sort(key=lambda m: (m.resource_type, m.resource_id))
        return FindOutput(query=query, strategy_used="resource_id", matches=matches)

    def _try_composite_id(self, query: str, resource_type: Optional[str]) -> Optional[FindOutput]:
        if ":" not in query:
            return None
        prefix, _, payload = query.partition(":")
        if not prefix or not payload:
            return None

        if prefix == "ngsiem":
            inner = self._try_rule_id(payload, resource_type)
            if inner is None:
                return FindOutput(
                    query=query,
                    strategy_used="composite_id_ngsiem",
                    matches=[],
                )
            return FindOutput(
                query=query,
                strategy_used="composite_id_ngsiem",
                matches=inner.matches,
            )

        if prefix in NON_IAC_PREFIXES:
            return FindOutput(
                query=query,
                strategy_used="composite_id_non_iac",
                matches=[],
                non_iac_info=NON_IAC_PREFIXES[prefix],
            )

        return None
