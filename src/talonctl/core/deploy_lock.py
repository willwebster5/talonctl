"""
Advisory File Lock for Deployment Operations

Prevents concurrent deployments from corrupting state by using
fcntl.flock() on a dedicated lock file. The lock is automatically
released when the process exits (even on SIGKILL).
"""

import fcntl
import os
import json
import time
import logging
from pathlib import Path
from contextlib import contextmanager
from datetime import datetime, timezone

logger = logging.getLogger(__name__)


class DeploymentLockError(Exception):
    """Raised when a deployment lock cannot be acquired"""

    pass


@contextmanager
def deployment_lock(lock_dir: Path, timeout: int = 5, lock_filename: str = "deploy.lock"):
    """
    Acquire an advisory file lock for deployment operations.

    Args:
        lock_dir: Directory for the lock file (typically .crowdstrike/)
        timeout: Seconds to wait before failing (0 = fail immediately)
        lock_filename: Name of the lock file

    Raises:
        DeploymentLockError: If lock cannot be acquired within timeout

    Yields:
        Path to the lock file (for diagnostics)
    """
    lock_path = lock_dir / lock_filename
    lock_dir.mkdir(parents=True, exist_ok=True)

    fd = os.open(str(lock_path), os.O_CREAT | os.O_RDWR)
    try:
        deadline = time.monotonic() + timeout
        acquired = False

        while True:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                acquired = True
                break
            except BlockingIOError:
                if time.monotonic() >= deadline:
                    break
                time.sleep(0.2)

        if not acquired:
            try:
                os.lseek(fd, 0, os.SEEK_SET)
                existing = os.read(fd, 4096).decode()
                info = json.loads(existing) if existing.strip() else {}
            except Exception:
                info = {}
            raise DeploymentLockError(
                f"Another deployment is in progress. "
                f"Lock held since: {info.get('acquired_at', 'unknown')}, "
                f"PID: {info.get('pid', 'unknown')}. "
                f"If stale, delete {lock_path}"
            )

        os.ftruncate(fd, 0)
        os.lseek(fd, 0, os.SEEK_SET)
        metadata = json.dumps(
            {"pid": os.getpid(), "acquired_at": datetime.now(timezone.utc).isoformat(), "command": "apply"}
        )
        os.write(fd, metadata.encode())
        os.fsync(fd)

        logger.debug(f"Deployment lock acquired: {lock_path}")
        yield lock_path

    finally:
        try:
            os.ftruncate(fd, 0)
            fcntl.flock(fd, fcntl.LOCK_UN)
        except Exception:
            pass
        os.close(fd)
