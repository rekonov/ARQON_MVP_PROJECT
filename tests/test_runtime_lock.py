from __future__ import annotations

import json

import pytest

from arqon_guardian.runtime_lock import RuntimeLock, RuntimeLockError


def test_runtime_lock_blocks_second_instance(tmp_path):
    lock_path = tmp_path / "arqon-runtime.lock"
    first = RuntimeLock(lock_path)
    second = RuntimeLock(lock_path)

    first.acquire()
    try:
        with pytest.raises(RuntimeLockError):
            second.acquire()
    finally:
        first.release()


def test_runtime_lock_clears_stale_pid_file(tmp_path):
    lock_path = tmp_path / "arqon-runtime.lock"
    lock_path.write_text(
        json.dumps({"pid": 999_999, "created_at_utc": "2026-01-01T00:00:00Z"}, ensure_ascii=True),
        encoding="utf-8",
    )

    lock = RuntimeLock(lock_path)
    lock.acquire()
    lock.release()

