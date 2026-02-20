from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path
import threading
from typing import Any


class AuditLogger:
    def __init__(self, state_dir: Path):
        self.state_dir = state_dir
        self.log_file = state_dir / "audit-log.jsonl"
        self.state_dir.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()

    def log(
        self,
        *,
        action: str,
        status: str,
        actor: str = "system",
        source: str = "agent",
        details: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        payload = {
            "timestamp_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "action": action,
            "status": status,
            "actor": actor,
            "source": source,
            "details": details or {},
        }
        raw = json.dumps(payload, ensure_ascii=True)
        with self._lock:
            with self.log_file.open("a", encoding="utf-8") as stream:
                stream.write(raw)
                stream.write("\n")
        return payload

    def tail(self, limit: int = 100) -> list[dict[str, Any]]:
        target = max(1, min(1000, int(limit)))
        if not self.log_file.exists():
            return []
        with self._lock:
            lines = self.log_file.read_text(encoding="utf-8").splitlines()
        output: list[dict[str, Any]] = []
        for line in lines[-target:]:
            try:
                payload = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(payload, dict):
                output.append(payload)
        return output

