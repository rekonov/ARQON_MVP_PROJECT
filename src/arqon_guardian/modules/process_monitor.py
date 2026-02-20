from __future__ import annotations

import logging
import threading
from typing import Callable

import psutil

from arqon_guardian.rules import Decision, RuleEvaluator


LOGGER = logging.getLogger(__name__)

ProcessBlockCallback = Callable[[int, str, Decision], None]


class ProcessMonitor:
    def __init__(
        self,
        evaluator: RuleEvaluator,
        poll_interval_sec: float,
        on_blocked_process: ProcessBlockCallback | None = None,
    ):
        self._evaluator = evaluator
        self._poll_interval_sec = max(0.5, poll_interval_sec)
        self._on_blocked_process = on_blocked_process
        self._stop_event = threading.Event()
        self._seen_pids: set[int] = set()
        self._thread = threading.Thread(
            target=self._run,
            name="lume-process-monitor",
            daemon=True,
        )

    def start(self) -> None:
        self._seed_existing_processes()
        self._thread.start()
        LOGGER.info("Process monitor started")

    def stop(self) -> None:
        self._stop_event.set()

    def join(self, timeout: float | None = None) -> None:
        if self._thread.is_alive():
            self._thread.join(timeout=timeout)

    def is_alive(self) -> bool:
        return self._thread.is_alive()

    def _seed_existing_processes(self) -> None:
        for process in psutil.process_iter(["pid"]):
            pid = process.info.get("pid")
            if isinstance(pid, int):
                self._seen_pids.add(pid)

    def _run(self) -> None:
        while not self._stop_event.is_set():
            for process in psutil.process_iter(["pid", "name", "exe", "cmdline"]):
                pid = process.info.get("pid")
                if not isinstance(pid, int):
                    continue
                if pid in self._seen_pids:
                    continue
                self._seen_pids.add(pid)
                self._handle_new_process(process)

            self._stop_event.wait(self._poll_interval_sec)

        LOGGER.info("Process monitor stopped")

    def _handle_new_process(self, process: psutil.Process) -> None:
        pid = process.info.get("pid")
        name = process.info.get("name") or "unknown"
        exe = process.info.get("exe")
        cmdline = process.info.get("cmdline") or []

        decision = self._evaluator.evaluate_process(name, exe, cmdline)
        if not decision.should_block:
            return

        if not isinstance(pid, int):
            return

        try:
            process.terminate()
            try:
                process.wait(timeout=2)
            except psutil.TimeoutExpired:
                process.kill()
                process.wait(timeout=2)
        except (psutil.AccessDenied, psutil.NoSuchProcess, psutil.ZombieProcess):
            LOGGER.warning("Failed to terminate blocked process pid=%s name=%s", pid, name)
            return

        LOGGER.warning(
            "Blocked process pid=%s name=%s reasons=%s",
            pid,
            name,
            ",".join(decision.reasons),
        )
        if self._on_blocked_process:
            self._on_blocked_process(pid, name, decision)
