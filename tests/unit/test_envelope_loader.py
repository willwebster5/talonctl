import pytest
from talonctl.core.envelope_loader import load_envelopes


def _write(tmp_path, name, text):
    p = tmp_path / name
    p.write_text(text)
    return p


def test_load_single_v2_resource(tmp_path):
    p = _write(
        tmp_path,
        "d.yaml",
        """
apiVersion: talon/v2
kind: Detection
metadata:
  resource_id: ex___susp
  name: Ex
spec:
  severity: 70
""",
    )
    envs = load_envelopes(p)
    assert len(envs) == 1
    assert envs[0].kind == "Detection"
    assert envs[0].resource_id == "ex___susp"


def test_load_multi_document_v2(tmp_path):
    p = _write(
        tmp_path,
        "multi.yaml",
        """
apiVersion: talon/v2
kind: LookupFile
metadata: {resource_id: lf1}
spec: {format: csv}
---
apiVersion: talon/v2
kind: Detection
metadata: {resource_id: d1}
spec: {severity: 1}
""",
    )
    envs = load_envelopes(p)
    assert [e.resource_id for e in envs] == ["lf1", "d1"]


def test_load_top_level_list_v2(tmp_path):
    p = _write(
        tmp_path,
        "list.yaml",
        """
- apiVersion: talon/v2
  kind: LookupFile
  metadata: {resource_id: lf1}
  spec: {format: csv}
- apiVersion: talon/v2
  kind: Detection
  metadata: {resource_id: d1}
  spec: {severity: 1}
""",
    )
    envs = load_envelopes(p)
    assert {e.resource_id for e in envs} == {"lf1", "d1"}


def test_load_v1_document_normalizes_via_default_type(tmp_path):
    p = _write(
        tmp_path,
        "legacy.yaml",
        """
resource_id: legacy_det
name: Legacy
status: active
severity: 50
""",
    )
    envs = load_envelopes(p, default_resource_type="detection")
    assert len(envs) == 1
    assert envs[0].kind == "Detection"
    assert envs[0].spec["enabled"] is True


def test_v2_doc_rejects_authored_status(tmp_path):
    p = _write(
        tmp_path,
        "bad.yaml",
        """
apiVersion: talon/v2
kind: Detection
metadata: {resource_id: d1}
spec: {severity: 1}
status: {rule_id: abc}
""",
    )
    with pytest.raises(ValueError, match="status"):
        load_envelopes(p)


def test_v2_doc_rejects_unknown_kind(tmp_path):
    p = _write(
        tmp_path,
        "bad2.yaml",
        """
apiVersion: talon/v2
kind: Nonsense
metadata: {resource_id: d1}
spec: {x: 1}
""",
    )
    with pytest.raises(ValueError, match="kind"):
        load_envelopes(p)
