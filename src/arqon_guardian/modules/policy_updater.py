from __future__ import annotations

import logging
from pathlib import Path
import threading

from arqon_guardian.audit import AuditLogger
from arqon_guardian.events import EventStore
from arqon_guardian.policy_pack import (
    PolicyPackError,
    apply_policy_pack,
    pull_policy_pack,
    read_secrets,
)


LOGGER = logging.getLogger(__name__)


class PolicyUpdater:
    def __init__(
        self,
        *,
        enabled: bool,
        url: str,
        interval_sec: float,
        apply_on_startup: bool,
        secret_file: Path | None,
        keyring_file: Path | None,
        config_path: Path,
        state_dir: Path,
        event_store: EventStore | None = None,
        audit_logger: AuditLogger | None = None,
    ):
        self.enabled = bool(enabled and str(url).strip())
        self.url = str(url).strip()
        self.interval_sec = max(60.0, float(interval_sec))
        self.apply_on_startup = bool(apply_on_startup)
        self.secret_file = secret_file
        self.keyring_file = keyring_file
        self.config_path = config_path
        self.state_dir = state_dir
        self.event_store = event_store
        self.audit_logger = audit_logger

        self._stop_event = threading.Event()
        self._thread = threading.Thread(target=self._run, name="arqon-policy-updater", daemon=True)
        self.state_dir.mkdir(parents=True, exist_ok=True)

    def start(self) -> None:
        if not self.enabled:
            LOGGER.info("Policy updater disabled")
            return
        self._thread.start()
        LOGGER.info("Policy updater started (url=%s)", self.url)

    def stop(self) -> None:
        self._stop_event.set()

    def join(self, timeout: float | None = None) -> None:
        if self._thread.is_alive():
            self._thread.join(timeout=timeout)
            LOGGER.info("Policy updater stopped")

    def is_alive(self) -> bool:
        return self._thread.is_alive()

    def _run(self) -> None:
        if self.apply_on_startup:
            self._run_once()

        while not self._stop_event.wait(self.interval_sec):
            self._run_once()

    def _run_once(self) -> None:
        if not self.enabled:
            return

        try:
            secrets = read_secrets(secret_file=self.secret_file, keyring_file=self.keyring_file)
            pack = pull_policy_pack(self.url, timeout_sec=6.0)
            result = apply_policy_pack(
                pack=pack,
                config_path=self.config_path,
                secrets=secrets,
                state_dir=self.state_dir,
                enforce_monotonic_version=True,
                allow_replay=False,
            )
            LOGGER.info("Policy pack applied from updater: version=%s", result.get("version"))
            if self.event_store:
                self.event_store.append(
                    event_type="policy_update",
                    level="info",
                    message="Signed policy pack applied",
                    data=result,
                )
            if self.audit_logger:
                self.audit_logger.log(
                    action="policy_update_apply",
                    status="success",
                    actor="system",
                    source="policy_updater",
                    details=result,
                )
        except PolicyPackError as error:
            LOGGER.warning("Policy updater error: %s", error)
            if self.event_store:
                self.event_store.append(
                    event_type="policy_update",
                    level="warning",
                    message="Policy update rejected",
                    data={"error": str(error)},
                )
            if self.audit_logger:
                self.audit_logger.log(
                    action="policy_update_apply",
                    status="rejected",
                    actor="system",
                    source="policy_updater",
                    details={"error": str(error)},
                )
        except Exception as error:  # pragma: no cover - runtime defensive path
            LOGGER.warning("Policy updater unexpected error: %s", error)
