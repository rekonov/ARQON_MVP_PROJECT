from __future__ import annotations

import logging
from pathlib import Path
import time

from arqon_guardian.audit import AuditLogger
from arqon_guardian.config import AppConfig
from arqon_guardian.events import EventStore
from arqon_guardian.modules.download_monitor import DownloadMonitor
from arqon_guardian.modules.firewall_manager import FirewallManager
from arqon_guardian.modules.local_api import LocalApiServer
from arqon_guardian.modules.policy_updater import PolicyUpdater
from arqon_guardian.modules.process_monitor import ProcessMonitor
from arqon_guardian.health import run_self_check
from arqon_guardian.quarantine import QuarantineManager
from arqon_guardian.reputation import ReputationService
from arqon_guardian.retention import RetentionManager
from arqon_guardian.rules import Decision, RuleEvaluator
from arqon_guardian.signature import SignatureInspector
from arqon_guardian.supervisor import RuntimeSupervisor


LOGGER = logging.getLogger(__name__)


class SecurityAgent:
    def __init__(self, config: AppConfig):
        self.config = config
        self.reputation = ReputationService(config.reputation_config)
        self.signature_inspector = SignatureInspector()
        self.evaluator = RuleEvaluator(
            config.rules,
            risk_config=config.risk_config,
            reputation_service=self.reputation,
            signature_inspector=self.signature_inspector,
        )
        self.quarantine = QuarantineManager(config.quarantine_dir, config.state_dir)
        self.event_store = EventStore(config.state_dir)
        self.audit_logger = AuditLogger(config.state_dir)
        self.firewall_manager = FirewallManager(config.state_dir, config.firewall_rule_prefix)
        watchdog_cfg = config.watchdog_config
        self._watchdog_enabled = bool(watchdog_cfg.get("enabled", True))
        self._watchdog_check_interval_sec = float(watchdog_cfg.get("check_interval_sec", 2.0))
        self._watchdog_max_restart_attempts = int(watchdog_cfg.get("max_restart_attempts", 3))
        self._supervisor: RuntimeSupervisor | None = None
        self._running = False
        self._started_at_utc: float | None = None

    def start(self) -> None:
        if self._running:
            return
        self._running = True
        self._started_at_utc = time.time()
        self.event_store.append(
            event_type="agent_start",
            level="info",
            message="ARQON agent starting",
            data={},
        )

        if self.config.startup_firewall_sync:
            try:
                result = self.firewall_manager.sync_blocked_hosts(self.config.blocked_hosts)
                LOGGER.info("Firewall initial sync: %s", result)
                self.event_store.append(
                    event_type="firewall_sync",
                    level="info",
                    message="Firewall sync completed",
                    data=result,
                )
                self.audit_logger.log(
                    action="firewall_sync",
                    status="success",
                    actor="system",
                    source="agent",
                    details=result,
                )
            except Exception as error:  # pragma: no cover - runtime defensive path
                LOGGER.warning("Firewall sync skipped: %s", error)
                self.event_store.append(
                    event_type="firewall_sync",
                    level="warning",
                    message="Firewall sync skipped",
                    data={"error": str(error)},
                )
                self.audit_logger.log(
                    action="firewall_sync",
                    status="failed",
                    actor="system",
                    source="agent",
                    details={"error": str(error)},
                )

        self._supervisor = RuntimeSupervisor(
            enabled=self._watchdog_enabled,
            check_interval_sec=self._watchdog_check_interval_sec,
            max_restart_attempts=self._watchdog_max_restart_attempts,
            event_store=self.event_store,
            audit_logger=self.audit_logger,
        )
        self._register_runtime_modules()
        self._supervisor.start()

        LOGGER.info("Security agent started")
        self.event_store.append(
            event_type="agent_start",
            level="info",
            message="ARQON agent started",
            data=self._status_snapshot(),
        )

    def run_forever(self) -> None:
        if not self._running:
            self.start()
        try:
            while True:
                time.sleep(1.0)
        except KeyboardInterrupt:
            LOGGER.info("Keyboard interrupt received, stopping agent")
        finally:
            self.stop()

    def stop(self) -> None:
        if not self._running:
            return
        if self._supervisor is not None:
            self._supervisor.stop()
            self._supervisor = None
        self._running = False
        LOGGER.info("Security agent stopped")
        self.event_store.append(
            event_type="agent_stop",
            level="info",
            message="ARQON agent stopped",
            data=self._status_snapshot(),
        )

    def _on_blocked_process(self, pid: int, name: str, decision: Decision) -> None:
        LOGGER.warning(
            "Blocked process event: pid=%s name=%s reasons=%s",
            pid,
            name,
            ",".join(decision.reasons),
        )
        self.event_store.append(
            event_type="blocked_process",
            level="warning",
            message=f"Blocked process: {name} ({pid})",
            data={
                "pid": pid,
                "name": name,
                "reasons": decision.reasons,
                "risk_score": decision.risk_score,
            },
        )

    def _on_blocked_file(self, source_path, quarantined_path, decision: Decision) -> None:
        LOGGER.warning(
            "Blocked file event: source=%s quarantine=%s reasons=%s",
            source_path,
            quarantined_path,
            ",".join(decision.reasons),
        )
        self.event_store.append(
            event_type="blocked_file",
            level="warning",
            message=f"Blocked file: {source_path}",
            data={
                "source_path": str(source_path),
                "quarantined_path": str(quarantined_path) if quarantined_path else None,
                "reasons": decision.reasons,
                "risk_score": decision.risk_score,
                "sha256": decision.sha256,
            },
        )

    def _status_snapshot(self) -> dict:
        uptime_sec = 0
        if self._started_at_utc:
            uptime_sec = int(max(0.0, time.time() - self._started_at_utc))
        module_states = self._supervisor.statuses() if self._supervisor else []
        return {
            "running": self._running,
            "modules": [item["name"] for item in module_states if item.get("alive")],
            "module_states": module_states,
            "uptime_sec": uptime_sec,
        }

    def _register_runtime_modules(self) -> None:
        if self._supervisor is None:
            return

        if self.config.process_monitor_enabled:
            self._supervisor.register("process_monitor", self._build_process_monitor)

        if self.config.download_monitor_enabled:
            self._supervisor.register("download_monitor", self._build_download_monitor)

        api_cfg = self.config.api_config
        if bool(api_cfg.get("enabled", True)):
            self._supervisor.register("local_api", self._build_local_api)

        updater_cfg = self.config.policy_updates_config
        updater_enabled = bool(updater_cfg.get("enabled", False))
        updater_url = str(updater_cfg.get("url", "")).strip()
        if updater_enabled and updater_url:
            self._supervisor.register("policy_updater", self._build_policy_updater)

        retention_cfg = self.config.retention_config
        if bool(retention_cfg.get("enabled", True)):
            self._supervisor.register("retention_manager", self._build_retention_manager)

    def _build_process_monitor(self) -> ProcessMonitor:
        return ProcessMonitor(
            evaluator=self.evaluator,
            poll_interval_sec=self.config.poll_interval_sec,
            on_blocked_process=self._on_blocked_process,
        )

    def _build_download_monitor(self) -> DownloadMonitor:
        return DownloadMonitor(
            watch_dir=self.config.downloads_dir,
            evaluator=self.evaluator,
            quarantine=self.quarantine,
            on_blocked_file=self._on_blocked_file,
        )

    def _build_local_api(self) -> LocalApiServer:
        api_cfg = self.config.api_config
        return LocalApiServer(
            evaluator=self.evaluator,
            quarantine=self.quarantine,
            host=str(api_cfg.get("host", "127.0.0.1")),
            port=int(api_cfg.get("port", 8765)),
            auth_key=str(api_cfg.get("auth_key", "")),
            admin_key=str(api_cfg.get("admin_key", "")),
            body_limit_bytes=int(api_cfg.get("body_limit_bytes", 65536)),
            rate_limit_enabled=bool(api_cfg.get("rate_limit_enabled", True)),
            rate_limit_requests=int(api_cfg.get("rate_limit_requests", 120)),
            rate_limit_window_sec=float(api_cfg.get("rate_limit_window_sec", 60)),
            admin_rate_limit_requests=int(api_cfg.get("admin_rate_limit_requests", 80)),
            event_store=self.event_store,
            dashboard_dir=self.config.project_root / "dashboard",
            status_provider=self._status_snapshot,
            audit_tail_provider=self.audit_logger.tail,
            self_check_provider=self._self_check_snapshot,
        )

    def _build_policy_updater(self) -> PolicyUpdater:
        updater_cfg = self.config.policy_updates_config
        secret_file = _resolve_optional_path(
            updater_cfg.get("private_key_file") or updater_cfg.get("secret_file"),
            self.config.path_base_dir,
        )
        keyring_file = _resolve_optional_path(
            updater_cfg.get("public_keyring_file") or updater_cfg.get("keyring_file"),
            self.config.path_base_dir,
        )
        return PolicyUpdater(
            enabled=bool(updater_cfg.get("enabled", False)),
            url=str(updater_cfg.get("url", "")),
            interval_sec=float(updater_cfg.get("interval_sec", 1800)),
            apply_on_startup=bool(updater_cfg.get("apply_on_startup", True)),
            secret_file=secret_file,
            keyring_file=keyring_file,
            config_path=self.config.config_path,
            state_dir=self.config.state_dir,
            event_store=self.event_store,
            audit_logger=self.audit_logger,
        )

    def _build_retention_manager(self) -> RetentionManager:
        return RetentionManager(
            state_dir=self.config.state_dir,
            quarantine_dir=self.config.quarantine_dir,
            project_root=self.config.project_root,
            config=self.config.retention_config,
            event_store=self.event_store,
            audit_logger=self.audit_logger,
        )

    def _self_check_snapshot(self, skip_bind_check: bool) -> dict:
        return run_self_check(self.config, check_bind=not bool(skip_bind_check))


def _resolve_optional_path(raw: object, base_dir: Path) -> Path | None:
    value = str(raw or "").strip()
    if not value:
        return None
    path = Path(value)
    if not path.is_absolute():
        path = (base_dir / path).resolve()
    return path
