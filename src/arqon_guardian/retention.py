from __future__ import annotations

from datetime import datetime, timedelta, timezone
import logging
from pathlib import Path
import shutil
import threading
from typing import Any

from arqon_guardian.audit import AuditLogger
from arqon_guardian.events import EventStore


LOGGER = logging.getLogger(__name__)


class RetentionManager:
    def __init__(
        self,
        *,
        state_dir: Path,
        quarantine_dir: Path,
        project_root: Path,
        config: dict[str, Any],
        event_store: EventStore | None = None,
        audit_logger: AuditLogger | None = None,
    ):
        self.state_dir = state_dir
        self.quarantine_dir = quarantine_dir
        self.project_root = project_root
        self.config = dict(config)
        self.event_store = event_store
        self.audit_logger = audit_logger

        self.enabled = bool(self.config.get("enabled", True))
        self.interval_sec = max(60.0, float(self.config.get("interval_sec", 3600)))
        self._stop_event = threading.Event()
        self._thread = threading.Thread(target=self._run_loop, name="arqon-retention", daemon=True)

    def start(self) -> None:
        if not self.enabled:
            LOGGER.info("Retention manager disabled")
            return
        self._thread.start()
        LOGGER.info("Retention manager started (interval=%s)", self.interval_sec)

    def stop(self) -> None:
        self._stop_event.set()

    def join(self, timeout: float | None = None) -> None:
        if self._thread.is_alive():
            self._thread.join(timeout=timeout)
            LOGGER.info("Retention manager stopped")

    def is_alive(self) -> bool:
        return self._thread.is_alive()

    def run_once(self) -> dict[str, Any]:
        result = run_retention(
            state_dir=self.state_dir,
            quarantine_dir=self.quarantine_dir,
            project_root=self.project_root,
            config=self.config,
        )
        if self.event_store and result.get("changed"):
            self.event_store.append(
                event_type="retention_cleanup",
                level="info",
                message="Retention cleanup completed",
                data=result,
            )
        if self.audit_logger:
            self.audit_logger.log(
                action="retention_cleanup",
                status="success",
                actor="system",
                source="retention_manager",
                details=result,
            )
        return result

    def _run_loop(self) -> None:
        self.run_once()
        while not self._stop_event.wait(self.interval_sec):
            try:
                self.run_once()
            except Exception as error:  # noqa: BLE001
                LOGGER.warning("Retention cleanup failed: %s", error)


def run_retention(
    *,
    state_dir: Path,
    quarantine_dir: Path,
    project_root: Path,
    config: dict[str, Any],
) -> dict[str, Any]:
    state_dir.mkdir(parents=True, exist_ok=True)
    quarantine_dir.mkdir(parents=True, exist_ok=True)

    changes: dict[str, int] = {}

    event_lines_removed = _trim_jsonl(state_dir / "events.jsonl", max_lines=int(config.get("max_event_lines", 20000)))
    audit_lines_removed = _trim_jsonl(
        state_dir / "audit-log.jsonl",
        max_lines=int(config.get("max_audit_lines", 20000)),
    )
    quarantine_log_removed = _trim_jsonl(
        state_dir / "quarantine-log.jsonl",
        max_lines=int(config.get("max_quarantine_log_lines", 10000)),
    )
    if event_lines_removed:
        changes["events_lines_removed"] = event_lines_removed
    if audit_lines_removed:
        changes["audit_lines_removed"] = audit_lines_removed
    if quarantine_log_removed:
        changes["quarantine_log_lines_removed"] = quarantine_log_removed

    quarantine_removed = _prune_quarantine_files(
        quarantine_dir=quarantine_dir,
        max_files=int(config.get("max_quarantine_files", 500)),
        max_age_days=float(config.get("max_quarantine_age_days", 30)),
    )
    if quarantine_removed:
        changes["quarantine_files_removed"] = quarantine_removed

    update_backups_removed = _prune_backup_dirs(
        backups_dir=project_root / "backups",
        max_dirs=int(config.get("max_update_backups", 20)),
    )
    if update_backups_removed:
        changes["update_backups_removed"] = update_backups_removed

    policy_backups_removed = _prune_backup_files(
        backup_dir=state_dir / "policy-backups",
        max_files=int(config.get("max_policy_backups", 120)),
    )
    if policy_backups_removed:
        changes["policy_backups_removed"] = policy_backups_removed

    privacy_backups_removed = _prune_backup_files(
        backup_dir=state_dir / "privacy-backups",
        max_files=int(config.get("max_privacy_backups", 120)),
    )
    if privacy_backups_removed:
        changes["privacy_backups_removed"] = privacy_backups_removed

    return {"changed": bool(changes), "changes": changes}


def _trim_jsonl(path: Path, *, max_lines: int) -> int:
    target_max = max(1, int(max_lines))
    if not path.exists() or not path.is_file():
        return 0
    lines = path.read_text(encoding="utf-8").splitlines()
    if len(lines) <= target_max:
        return 0
    kept = lines[-target_max:]
    path.write_text("\n".join(kept) + "\n", encoding="utf-8")
    return len(lines) - len(kept)


def _prune_quarantine_files(*, quarantine_dir: Path, max_files: int, max_age_days: float) -> int:
    files = sorted([item for item in quarantine_dir.glob("*") if item.is_file()], key=lambda p: p.stat().st_mtime)
    if not files:
        return 0
    removed = 0
    cutoff = datetime.now(timezone.utc) - timedelta(days=max(1.0, float(max_age_days)))

    for file_path in files:
        modified_at = datetime.fromtimestamp(file_path.stat().st_mtime, tz=timezone.utc)
        if modified_at < cutoff:
            file_path.unlink(missing_ok=True)
            removed += 1

    files = sorted([item for item in quarantine_dir.glob("*") if item.is_file()], key=lambda p: p.stat().st_mtime)
    max_allowed = max(1, int(max_files))
    overflow = max(0, len(files) - max_allowed)
    for file_path in files[:overflow]:
        file_path.unlink(missing_ok=True)
        removed += 1
    return removed


def _prune_backup_dirs(*, backups_dir: Path, max_dirs: int) -> int:
    if not backups_dir.exists() or not backups_dir.is_dir():
        return 0
    dirs = sorted([item for item in backups_dir.iterdir() if item.is_dir()], key=lambda p: p.stat().st_mtime)
    max_allowed = max(1, int(max_dirs))
    overflow = max(0, len(dirs) - max_allowed)
    removed = 0
    for folder in dirs[:overflow]:
        shutil.rmtree(folder, ignore_errors=True)
        removed += 1
    return removed


def _prune_backup_files(*, backup_dir: Path, max_files: int) -> int:
    if not backup_dir.exists() or not backup_dir.is_dir():
        return 0
    files = sorted([item for item in backup_dir.iterdir() if item.is_file()], key=lambda p: p.stat().st_mtime)
    max_allowed = max(1, int(max_files))
    overflow = max(0, len(files) - max_allowed)
    removed = 0
    for file_path in files[:overflow]:
        file_path.unlink(missing_ok=True)
        removed += 1
    return removed
