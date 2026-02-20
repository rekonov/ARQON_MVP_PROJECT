from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path
from typing import Any
import zipfile

from arqon_guardian.__init__ import __version__
from arqon_guardian.audit import AuditLogger
from arqon_guardian.config import AppConfig
from arqon_guardian.events import EventStore
from arqon_guardian.health import run_self_check
from arqon_guardian.quarantine import QuarantineManager


SENSITIVE_KEYS = {"auth_key", "admin_key", "api_key", "secret", "token", "password"}


def create_diagnostics_bundle(
    *,
    config: AppConfig,
    event_store: EventStore,
    audit_logger: AuditLogger,
    quarantine: QuarantineManager,
    output_path: Path,
    events_limit: int = 1000,
    audit_limit: int = 1000,
    quarantine_limit: int = 500,
    include_bind_check: bool = False,
) -> dict[str, Any]:
    output = output_path.expanduser().resolve()
    output.parent.mkdir(parents=True, exist_ok=True)

    events = event_store.tail(limit=events_limit)
    audit_records = audit_logger.tail(limit=audit_limit)
    quarantine_records = quarantine.tail_records(limit=quarantine_limit)
    event_summary = event_store.summary(limit=max(events_limit, 1000))
    self_check = run_self_check(config, check_bind=include_bind_check)

    metadata = {
        "bundle_schema": "arqon-diagnostics-bundle@1",
        "generated_at_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "arqon_version": __version__,
        "config_path": str(config.config_path),
        "limits": {
            "events_limit": int(events_limit),
            "audit_limit": int(audit_limit),
            "quarantine_limit": int(quarantine_limit),
        },
    }

    payloads: dict[str, Any] = {
        "metadata.json": metadata,
        "config.redacted.json": _redact_sensitive(config.data),
        "self_check.json": self_check,
        "events.summary.json": event_summary,
        "events.tail.json": events,
        "audit.tail.json": audit_records,
        "quarantine.tail.json": quarantine_records,
    }

    with zipfile.ZipFile(output, mode="w", compression=zipfile.ZIP_DEFLATED) as archive:
        for entry_name, payload in payloads.items():
            archive.writestr(entry_name, json.dumps(payload, ensure_ascii=True, indent=2))

    return {
        "created": True,
        "output": str(output),
        "counts": {
            "events": len(events),
            "audit_records": len(audit_records),
            "quarantine_records": len(quarantine_records),
        },
        "self_check_status": str(self_check.get("status", "unknown")),
    }


def _redact_sensitive(value: Any) -> Any:
    if isinstance(value, dict):
        output: dict[str, Any] = {}
        for key, item in value.items():
            key_str = str(key)
            if key_str.lower() in SENSITIVE_KEYS:
                output[key_str] = "***redacted***"
                continue
            output[key_str] = _redact_sensitive(item)
        return output
    if isinstance(value, list):
        return [_redact_sensitive(item) for item in value]
    return value
