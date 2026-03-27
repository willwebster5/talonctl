"""
Unit tests for deployment file locking
"""

import pytest
import os
import sys
import json
import tempfile
import threading
import time
from pathlib import Path
from unittest.mock import patch

# Add scripts directory to path
SCRIPTS_DIR = Path(__file__).parent.parent.parent / "scripts"
sys.path.insert(0, str(SCRIPTS_DIR))

from core.deploy_lock import deployment_lock, DeploymentLockError


class TestDeploymentLock:
    """Test suite for advisory file locking"""

    @pytest.fixture
    def lock_dir(self):
        """Create a temporary directory for lock files"""
        with tempfile.TemporaryDirectory() as td:
            yield Path(td)

    def test_acquire_and_release(self, lock_dir):
        """Lock is acquired, metadata written, then released cleanly"""
        with deployment_lock(lock_dir) as lock_path:
            assert lock_path.exists()
            with open(lock_path, 'r') as f:
                content = f.read()
            metadata = json.loads(content)
            assert metadata["pid"] == os.getpid()
            assert "acquired_at" in metadata

    def test_second_lock_raises_error(self, lock_dir):
        """A second lock attempt within timeout raises DeploymentLockError"""
        with deployment_lock(lock_dir, timeout=5):
            error_holder = []

            def try_lock():
                try:
                    with deployment_lock(lock_dir, timeout=1):
                        pass
                except DeploymentLockError as e:
                    error_holder.append(e)

            t = threading.Thread(target=try_lock)
            t.start()
            t.join(timeout=5)

            assert len(error_holder) == 1
            assert "Another deployment is in progress" in str(error_holder[0])

    def test_lock_released_after_exception(self, lock_dir):
        """Lock is released even when the body raises an exception"""
        with pytest.raises(ValueError, match="test error"):
            with deployment_lock(lock_dir):
                raise ValueError("test error")

        with deployment_lock(lock_dir, timeout=1) as lock_path:
            assert lock_path.exists()

    def test_lock_creates_directory(self):
        """Lock creates the lock directory if it doesn't exist"""
        with tempfile.TemporaryDirectory() as td:
            nested = Path(td) / "sub" / "dir"
            assert not nested.exists()
            with deployment_lock(nested, timeout=1):
                assert nested.exists()

    def test_zero_timeout_fails_immediately(self, lock_dir):
        """With timeout=0, a contested lock fails immediately"""
        import fcntl

        lock_path = lock_dir / "deploy.lock"
        fd = os.open(str(lock_path), os.O_CREAT | os.O_RDWR)
        fcntl.flock(fd, fcntl.LOCK_EX)

        try:
            with pytest.raises(DeploymentLockError):
                with deployment_lock(lock_dir, timeout=0):
                    pass
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
            os.close(fd)
