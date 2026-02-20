from __future__ import annotations

import json
import os
import time
from pathlib import Path

import psutil


class RuntimeLockError(RuntimeError):
    """Raised when runtime lock acquisition fails."""


class RuntimeLock:
    def __init__(self, lock_file: Path):
        self.lock_file = lock_file
        self._acquired = False

    def acquire(self) -> None:
        self.lock_file.parent.mkdir(parents=True, exist_ok=True)

        # Retry once after stale lock cleanup.
        for _ in range(2):
            try:
                handle = os.open(str(self.lock_file), os.O_CREAT | os.O_EXCL | os.O_WRONLY)
                payload = {
                    "pid": os.getpid(),
                    "created_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                    "cmdline": " ".join(psutil.Process().cmdline()),
                }
                raw = json.dumps(payload, ensure_ascii=True, indent=2)
                os.write(handle, raw.encode("utf-8"))
                os.close(handle)
                self._acquired = True
                return
            except FileExistsError:
                stale_cleared = self._clear_if_stale()
                if stale_cleared:
                    continue
                details = self._read_lock_details()
                raise RuntimeLockError(
                    "ARQON runtime already running"
                    if not details
                    else (
                        "ARQON runtime already running "
                        f"(pid={details.get('pid', 'unknown')} lock={self.lock_file})"
                    )
                ) from None

        raise RuntimeLockError(f"Failed to acquire runtime lock: {self.lock_file}")

    def release(self) -> None:
        if not self._acquired:
            return
        try:
            self.lock_file.unlink(missing_ok=True)
        finally:
            self._acquired = False

    def _read_lock_details(self) -> dict:
        try:
            raw = self.lock_file.read_text(encoding="utf-8")
            payload = json.loads(raw)
            if isinstance(payload, dict):
                return payload
        except Exception:
            return {}
        return {}

    def _clear_if_stale(self) -> bool:
        details = self._read_lock_details()
        pid_raw = details.get("pid")
        if not isinstance(pid_raw, int):
            return False
        if pid_raw <= 0:
            return False
        if psutil.pid_exists(pid_raw):
            return False
        try:
            self.lock_file.unlink(missing_ok=True)
            return True
        except Exception:
            return False
