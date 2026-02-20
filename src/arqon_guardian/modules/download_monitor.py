from __future__ import annotations

import logging
from pathlib import Path
import threading
import time
from typing import Callable

from watchdog.events import FileSystemEvent, FileSystemEventHandler
from watchdog.observers import Observer

from arqon_guardian.quarantine import QuarantineManager
from arqon_guardian.rules import Decision, RuleEvaluator


LOGGER = logging.getLogger(__name__)

BlockedFileCallback = Callable[[Path, Path | None, Decision], None]


class DownloadMonitor:
    def __init__(
        self,
        watch_dir: Path,
        evaluator: RuleEvaluator,
        quarantine: QuarantineManager,
        on_blocked_file: BlockedFileCallback | None = None,
    ):
        self.watch_dir = watch_dir
        self.evaluator = evaluator
        self.quarantine = quarantine
        self.on_blocked_file = on_blocked_file
        self._observer = Observer()
        self._handler = _DownloadEventHandler(self)
        self._lock = threading.Lock()
        self._last_seen: dict[str, float] = {}

    def start(self) -> None:
        self.watch_dir.mkdir(parents=True, exist_ok=True)
        self._observer.schedule(self._handler, str(self.watch_dir), recursive=False)
        self._observer.start()
        LOGGER.info("Download monitor started: %s", self.watch_dir)

    def stop(self) -> None:
        self._observer.stop()

    def join(self, timeout: float | None = None) -> None:
        self._observer.join(timeout=timeout)
        LOGGER.info("Download monitor stopped")

    def is_alive(self) -> bool:
        return self._observer.is_alive()

    def handle_path(self, path: Path) -> None:
        if not path.exists() or not path.is_file():
            return
        if not self._should_process(path):
            return

        if not _wait_until_file_stable(path):
            return

        decision = self.evaluator.evaluate_file(path)
        if not decision.should_block:
            return

        reason = ",".join(decision.reasons)
        quarantined_path = self.quarantine.quarantine_file(path, reason=reason, sha256=decision.sha256)
        if self.on_blocked_file:
            self.on_blocked_file(path, quarantined_path, decision)

    def _should_process(self, path: Path) -> bool:
        key = str(path.resolve())
        now = time.time()
        with self._lock:
            previous = self._last_seen.get(key)
            self._last_seen[key] = now
        if previous is None:
            return True
        return (now - previous) > 1.0


class _DownloadEventHandler(FileSystemEventHandler):
    def __init__(self, monitor: DownloadMonitor):
        super().__init__()
        self._monitor = monitor

    def on_created(self, event: FileSystemEvent) -> None:
        if event.is_directory:
            return
        self._monitor.handle_path(Path(event.src_path))

    def on_moved(self, event: FileSystemEvent) -> None:
        if event.is_directory:
            return
        destination = getattr(event, "dest_path", None)
        if destination:
            self._monitor.handle_path(Path(destination))

    def on_modified(self, event: FileSystemEvent) -> None:
        if event.is_directory:
            return
        self._monitor.handle_path(Path(event.src_path))


def _wait_until_file_stable(path: Path, timeout_sec: float = 6.0, interval_sec: float = 0.4) -> bool:
    deadline = time.time() + timeout_sec
    previous_size = -1

    while time.time() < deadline:
        try:
            current_size = path.stat().st_size
            if current_size > 0 and current_size == previous_size:
                return True
            previous_size = current_size
        except OSError:
            return False
        time.sleep(interval_sec)

    return False
