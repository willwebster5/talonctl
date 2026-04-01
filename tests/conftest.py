"""Pytest configuration for talonctl unit tests."""

import os
import sys

# Add scripts/ to sys.path so tests can import providers, core modules, etc.
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../scripts'))
