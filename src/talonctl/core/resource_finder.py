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
        return FindOutput(query=query, strategy_used="none", matches=[])
