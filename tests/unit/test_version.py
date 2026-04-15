"""Test that the package version is accessible and well-formed."""

import re

from talonctl import __version__


def test_version_is_string():
    assert isinstance(__version__, str)


def test_version_is_not_dev_fallback():
    """Ensure the version is resolved, not the fallback."""
    assert __version__ != "0.0.0.dev0", (
        "Version fell through to dev fallback. Run 'pip install -e .' to install the package."
    )


def test_version_format():
    """Version should start with a digit (PEP 440)."""
    assert re.match(r"^\d+\.", __version__), f"Version '{__version__}' does not start with a digit"
