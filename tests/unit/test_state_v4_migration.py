import json
import logging
import shutil
from pathlib import Path

from talonctl.core.state_manager import StateManager

FIXTURES = Path(__file__).parent.parent / "fixtures" / "state"


def _seed(tmp_path: Path, fixture_name: str) -> Path:
    """Copy a fixture state file into a temp dir and return its path."""
    dst = tmp_path / "deployed_state.json"
    shutil.copy(FIXTURES / fixture_name, dst)
    return dst


def test_clean_v3_upgrades_to_v4_in_memory(tmp_path):
    state_file = _seed(tmp_path, "v3_clean.json")
    mgr = StateManager(state_file)
    assert mgr.export_to_dict()["version"] == "4.0"


def test_clean_v3_emits_no_ambiguous_warning(tmp_path, caplog):
    state_file = _seed(tmp_path, "v3_clean.json")
    with caplog.at_level(logging.WARNING):
        StateManager(state_file)
    assert "ambiguous" not in caplog.text.lower()


def test_clean_keys_are_preserved(tmp_path):
    state_file = _seed(tmp_path, "v3_clean.json")
    mgr = StateManager(state_file)
    dets = mgr.export_to_dict()["resources"]["detection"]
    assert "example_source___suspicious_upload" in dets


def test_ambiguous_keys_upgrade_to_v4_and_warn_by_name(tmp_path, caplog):
    state_file = _seed(tmp_path, "v3_ambiguous.json")
    with caplog.at_level(logging.WARNING):
        mgr = StateManager(state_file)
    assert mgr.export_to_dict()["version"] == "4.0"
    assert "ambiguous" in caplog.text.lower()
    assert "detection.Example Source - Legacy Display Name Rule" in caplog.text
    assert "saved_search.Example Source - Legacy Saved Search" in caplog.text


def test_ambiguous_keys_left_untouched(tmp_path):
    state_file = _seed(tmp_path, "v3_ambiguous.json")
    mgr = StateManager(state_file)
    res = mgr.export_to_dict()["resources"]
    assert "Example Source - Legacy Display Name Rule" in res["detection"]
    assert "example_source___suspicious_upload" in res["detection"]
    assert "Example Source - Legacy Saved Search" in res["saved_search"]


def test_migration_is_lazy_no_disk_write_on_load(tmp_path):
    state_file = _seed(tmp_path, "v3_clean.json")
    StateManager(state_file)  # load only, no save()
    on_disk = json.loads(state_file.read_text())
    assert on_disk["version"] == "3.0"  # disk untouched until save()


def test_save_persists_v4_to_disk(tmp_path):
    state_file = _seed(tmp_path, "v3_clean.json")
    mgr = StateManager(state_file)
    mgr.save()
    on_disk = json.loads(state_file.read_text())
    assert on_disk["version"] == "4.0"


def test_v4_file_is_a_noop(tmp_path, caplog):
    state_file = _seed(tmp_path, "v3_clean.json")
    StateManager(state_file).save()  # now v4 on disk
    with caplog.at_level(logging.WARNING):
        mgr = StateManager(state_file)  # reload an already-v4 file
    assert mgr.export_to_dict()["version"] == "4.0"
    assert "ambiguous" not in caplog.text.lower()
