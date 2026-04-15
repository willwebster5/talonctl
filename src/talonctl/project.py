"""Project root detection for talonctl projects."""

from pathlib import Path


def find_project_root(start: Path | None = None) -> Path:
    """Find the talonctl project root by walking up from start looking for .crowdstrike/.

    Similar to how git finds .git/. If not found, returns start directory.

    Args:
        start: Directory to start searching from. Defaults to CWD.

    Returns:
        Path to the project root directory.
    """
    if start is None:
        start = Path.cwd()
    start = start.resolve()

    current = start
    while True:
        if (current / ".crowdstrike").is_dir():
            return current
        parent = current.parent
        if parent == current:
            # Hit filesystem root without finding marker
            return start
        current = parent
