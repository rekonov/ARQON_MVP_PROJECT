from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import json
import logging
from pathlib import Path
import shutil
from uuid import uuid4


LOGGER = logging.getLogger(__name__)


@dataclass(slots=True)
class QuarantineRecord:
    timestamp_utc: str
    original_path: str
    quarantined_path: str
    reason: str
    sha256: str | None
    size_bytes: int


class QuarantineManager:
    def __init__(self, quarantine_dir: Path, state_dir: Path):
        self.quarantine_dir = quarantine_dir
        self.state_dir = state_dir
        self.log_file = state_dir / "quarantine-log.jsonl"
        self.quarantine_dir.mkdir(parents=True, exist_ok=True)
        self.state_dir.mkdir(parents=True, exist_ok=True)

    def quarantine_file(
        self,
        file_path: Path,
        reason: str,
        sha256: str | None = None,
    ) -> Path | None:
        if not file_path.exists() or not file_path.is_file():
            LOGGER.warning("Quarantine skipped (file missing): %s", file_path)
            return None

        timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        destination_name = f"{timestamp}_{uuid4().hex[:8]}_{file_path.name}"
        destination = self.quarantine_dir / destination_name

        try:
            size_bytes = file_path.stat().st_size
            shutil.move(str(file_path), str(destination))
        except OSError as error:
            LOGGER.exception("Failed to quarantine %s: %s", file_path, error)
            return None

        record = QuarantineRecord(
            timestamp_utc=timestamp,
            original_path=str(file_path),
            quarantined_path=str(destination),
            reason=reason,
            sha256=sha256,
            size_bytes=size_bytes,
        )
        self._append_record(record)
        LOGGER.warning("File quarantined: %s -> %s (%s)", file_path, destination, reason)
        return destination

    def _append_record(self, record: QuarantineRecord) -> None:
        payload = {
            "timestamp_utc": record.timestamp_utc,
            "original_path": record.original_path,
            "quarantined_path": record.quarantined_path,
            "reason": record.reason,
            "sha256": record.sha256,
            "size_bytes": record.size_bytes,
        }
        with self.log_file.open("a", encoding="utf-8") as stream:
            stream.write(json.dumps(payload, ensure_ascii=True))
            stream.write("\n")

    def tail_records(self, limit: int = 100) -> list[dict]:
        target = max(1, min(1000, int(limit)))
        if not self.log_file.exists():
            return []
        lines = self.log_file.read_text(encoding="utf-8").splitlines()
        output: list[dict] = []
        for line in lines[-target:]:
            try:
                payload = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(payload, dict):
                output.append(payload)
        return output
