"""Tests for talonctl project root detection."""

import os
import tempfile
from pathlib import Path

import pytest

from talonctl.project import find_project_root


class TestFindProjectRoot:
    def test_finds_root_by_crowdstrike_dir(self, tmp_path):
        """Should find root when .crowdstrike/ exists."""
        (tmp_path / ".crowdstrike").mkdir()
        result = find_project_root(start=tmp_path)
        assert result == tmp_path

    def test_finds_root_from_subdirectory(self, tmp_path):
        """Should walk up and find root from a nested directory."""
        (tmp_path / ".crowdstrike").mkdir()
        nested = tmp_path / "resources" / "detections"
        nested.mkdir(parents=True)
        result = find_project_root(start=nested)
        assert result == tmp_path

    def test_returns_cwd_when_no_marker(self, tmp_path):
        """Should return start directory when no .crowdstrike/ found."""
        result = find_project_root(start=tmp_path)
        assert result == tmp_path

    def test_stops_at_filesystem_root(self, tmp_path):
        """Should not infinite-loop when no marker exists."""
        deeply_nested = tmp_path / "a" / "b" / "c" / "d"
        deeply_nested.mkdir(parents=True)
        result = find_project_root(start=deeply_nested)
        assert result == deeply_nested
