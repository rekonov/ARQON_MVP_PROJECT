from __future__ import annotations

import csv
from datetime import datetime, timezone
import json
from pathlib import Path
import threading
from typing import Any


LEVEL_PRIORITY: dict[str, int] = {
    "debug": 10,
    "info": 20,
    "warning": 30,
    "error": 40,
    "critical": 50,
}


class EventStore:
    def __init__(self, state_dir: Path):
        self.state_dir = state_dir
        self.events_file = state_dir / "events.jsonl"
        self.state_dir.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()

    def append(
        self,
        event_type: str,
        level: str,
        message: str,
        data: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        payload = {
            "timestamp_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "type": event_type,
            "level": level,
            "message": message,
            "data": data or {},
        }
        raw = json.dumps(payload, ensure_ascii=True)
        with self._lock:
            with self.events_file.open("a", encoding="utf-8") as stream:
                stream.write(raw)
                stream.write("\n")
        return payload

    def tail(self, limit: int = 100) -> list[dict[str, Any]]:
        target = max(1, min(1000, int(limit)))
        if not self.events_file.exists():
            return []

        with self._lock:
            lines = self.events_file.read_text(encoding="utf-8").splitlines()

        output: list[dict[str, Any]] = []
        for line in lines[-target:]:
            try:
                payload = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(payload, dict):
                output.append(payload)
        return output

    def summary(self, limit: int = 1000) -> dict[str, Any]:
        recent = self.tail(limit=limit)
        counts_by_type: dict[str, int] = {}
        counts_by_level: dict[str, int] = {}
        for item in recent:
            event_type = str(item.get("type", "unknown"))
            level = str(item.get("level", "info"))
            counts_by_type[event_type] = counts_by_type.get(event_type, 0) + 1
            counts_by_level[level] = counts_by_level.get(level, 0) + 1
        return {
            "count": len(recent),
            "by_type": counts_by_type,
            "by_level": counts_by_level,
        }

    def query(
        self,
        *,
        limit: int = 100,
        min_level: str = "info",
    ) -> list[dict[str, Any]]:
        target = max(1, min(10000, int(limit)))
        minimum = _normalize_level(min_level, default="info")
        minimum_score = LEVEL_PRIORITY[minimum]

        filtered: list[dict[str, Any]] = []
        for payload in self._read_all():
            level = _normalize_level(str(payload.get("level", "info")), default="info")
            if LEVEL_PRIORITY[level] >= minimum_score:
                filtered.append(payload)
        return filtered[-target:]

    def incident_records(self, limit: int = 1000, min_level: str = "warning") -> list[dict[str, Any]]:
        return self.query(limit=limit, min_level=min_level)

    def export_incidents(
        self,
        *,
        output_path: Path,
        export_format: str,
        limit: int = 1000,
        min_level: str = "warning",
    ) -> dict[str, Any]:
        fmt = str(export_format).strip().lower()
        if fmt not in {"json", "csv"}:
            raise ValueError("export_format must be one of: json, csv")

        records = self.incident_records(limit=limit, min_level=min_level)
        output = output_path.resolve()
        output.parent.mkdir(parents=True, exist_ok=True)

        if fmt == "json":
            payload = {
                "exported_at_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                "count": len(records),
                "min_level": _normalize_level(min_level, default="warning"),
                "incidents": records,
            }
            output.write_text(
                json.dumps(payload, ensure_ascii=True, indent=2),
                encoding="utf-8",
            )
        else:
            with output.open("w", encoding="utf-8", newline="") as stream:
                writer = csv.DictWriter(
                    stream,
                    fieldnames=["timestamp_utc", "type", "level", "message", "data_json"],
                )
                writer.writeheader()
                for record in records:
                    writer.writerow(
                        {
                            "timestamp_utc": str(record.get("timestamp_utc", "")),
                            "type": str(record.get("type", "")),
                            "level": str(record.get("level", "")),
                            "message": str(record.get("message", "")),
                            "data_json": json.dumps(record.get("data", {}), ensure_ascii=True),
                        }
                    )

        return {
            "output": str(output),
            "format": fmt,
            "count": len(records),
            "min_level": _normalize_level(min_level, default="warning"),
        }

    def _read_all(self) -> list[dict[str, Any]]:
        if not self.events_file.exists():
            return []

        with self._lock:
            lines = self.events_file.read_text(encoding="utf-8").splitlines()

        output: list[dict[str, Any]] = []
        for line in lines:
            try:
                payload = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(payload, dict):
                output.append(payload)
        return output


def _normalize_level(raw: str, *, default: str) -> str:
    normalized = str(raw).strip().lower()
    if normalized in LEVEL_PRIORITY:
        return normalized
    return default
