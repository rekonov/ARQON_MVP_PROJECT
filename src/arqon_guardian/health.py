from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import os
from pathlib import Path
import socket
import tempfile
from typing import Any

from arqon_guardian.config import AppConfig, detect_project_root


@dataclass(frozen=True)
class HealthCheckResult:
    name: str
    status: str
    message: str
    details: dict[str, Any]


def run_self_check(
    config: AppConfig,
    *,
    check_bind: bool = True,
) -> dict[str, Any]:
    checks: list[HealthCheckResult] = []

    checks.append(
        _check_directory_write_access(
            "state_dir_access",
            config.state_dir,
            create_if_missing=True,
        )
    )
    checks.append(
        _check_directory_write_access(
            "quarantine_dir_access",
            config.quarantine_dir,
            create_if_missing=True,
        )
    )
    checks.append(
        _check_directory_write_access(
            "downloads_dir_access",
            config.downloads_dir,
            create_if_missing=True,
        )
    )
    checks.append(_check_api_auth_config(config))
    checks.append(_check_policy_update_material(config))
    checks.append(_check_project_layout())

    if check_bind and bool(config.api_config.get("enabled", True)):
        checks.append(_check_api_bind(config))
    elif bool(config.api_config.get("enabled", True)):
        checks.append(
            HealthCheckResult(
                name="api_bind_check",
                status="warning",
                message="API bind check skipped",
                details={},
            )
        )

    severity_order = {"ok": 0, "warning": 1, "error": 2}
    highest = "ok"
    counts = {"ok": 0, "warning": 0, "error": 0}
    for item in checks:
        counts[item.status] = counts.get(item.status, 0) + 1
        if severity_order[item.status] > severity_order[highest]:
            highest = item.status

    return {
        "timestamp_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "status": highest,
        "counts": counts,
        "config_path": str(config.config_path),
        "checks": [
            {
                "name": item.name,
                "status": item.status,
                "message": item.message,
                "details": item.details,
            }
            for item in checks
        ],
    }


def health_exit_code(payload: dict[str, Any], *, strict: bool) -> int:
    status = str(payload.get("status", "error")).lower()
    if status == "error":
        return 20
    if strict and status == "warning":
        return 15
    return 0


def _check_directory_write_access(
    name: str,
    target_dir: Path,
    *,
    create_if_missing: bool,
) -> HealthCheckResult:
    try:
        if create_if_missing:
            target_dir.mkdir(parents=True, exist_ok=True)
        if not target_dir.exists() or not target_dir.is_dir():
            return HealthCheckResult(
                name=name,
                status="error",
                message="Directory is missing",
                details={"path": str(target_dir)},
            )

        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            suffix=".tmp",
            prefix="arqon-health-",
            dir=target_dir,
            delete=True,
        ) as stream:
            stream.write("ok")
            stream.flush()

        return HealthCheckResult(
            name=name,
            status="ok",
            message="Directory write access is healthy",
            details={"path": str(target_dir)},
        )
    except Exception as error:
        return HealthCheckResult(
            name=name,
            status="error",
            message="Directory write access failed",
            details={"path": str(target_dir), "error": str(error)},
        )


def _check_api_auth_config(config: AppConfig) -> HealthCheckResult:
    api_cfg = config.api_config
    api_raw = config.data.get("api", {}) if isinstance(config.data.get("api"), dict) else {}
    auth_key_ref = str(api_raw.get("auth_key_ref", "")).strip()
    admin_key_ref = str(api_raw.get("admin_key_ref", "")).strip()
    user_key = str(api_cfg.get("auth_key", "")).strip()
    admin_key = str(api_cfg.get("admin_key", "")).strip()
    warnings: list[str] = []

    if not user_key:
        return HealthCheckResult(
            name="api_auth_key",
            status="error",
            message="api.auth_key is empty",
            details={
                "auth_key_ref": auth_key_ref,
                "admin_key_ref": admin_key_ref,
                "secret_store_file": str(config.secret_store_file),
            },
        )
    if user_key == "change-me-arqon":
        warnings.append("api.auth_key still uses default value")
    if len(user_key) < 12:
        warnings.append("api.auth_key is shorter than 12 characters")
    if not admin_key:
        warnings.append("api.admin_key is empty (fallbacks to api.auth_key)")

    if warnings:
        return HealthCheckResult(
            name="api_auth_key",
            status="warning",
            message="API auth settings need hardening",
            details={
                "warnings": warnings,
                "auth_key_ref": auth_key_ref,
                "admin_key_ref": admin_key_ref,
                "secret_store_file": str(config.secret_store_file),
            },
        )

    return HealthCheckResult(
        name="api_auth_key",
        status="ok",
        message="API auth settings are healthy",
        details={
            "auth_key_ref": auth_key_ref,
            "admin_key_ref": admin_key_ref,
            "secret_store_file": str(config.secret_store_file),
        },
    )


def _check_policy_update_material(config: AppConfig) -> HealthCheckResult:
    updates_cfg = config.policy_updates_config
    enabled = bool(updates_cfg.get("enabled", False))
    url = str(updates_cfg.get("url", "")).strip()

    if not enabled:
        return HealthCheckResult(
            name="policy_update_material",
            status="ok",
            message="Policy updater is disabled",
            details={},
        )

    if not url:
        return HealthCheckResult(
            name="policy_update_material",
            status="error",
            message="policy_updates.url is empty while updater is enabled",
            details={},
        )

    secret_raw = str(updates_cfg.get("private_key_file") or updates_cfg.get("secret_file", "")).strip()
    if not secret_raw:
        return HealthCheckResult(
            name="policy_update_material",
            status="error",
            message="policy_updates.private_key_file is empty",
            details={},
        )

    secret_path = Path(os.path.expandvars(os.path.expanduser(secret_raw)))
    if not secret_path.is_absolute():
        secret_path = (config.path_base_dir / secret_path).resolve()
    if not secret_path.exists() or not secret_path.is_file():
        return HealthCheckResult(
            name="policy_update_material",
            status="error",
            message="policy_updates.private_key_file does not exist",
            details={"private_key_file": str(secret_path)},
        )

    keyring_raw = str(updates_cfg.get("public_keyring_file") or updates_cfg.get("keyring_file", "")).strip()
    keyring_path: Path | None = None
    if keyring_raw:
        keyring_path = Path(os.path.expandvars(os.path.expanduser(keyring_raw)))
        if not keyring_path.is_absolute():
            keyring_path = (config.path_base_dir / keyring_path).resolve()
        if not keyring_path.exists() or not keyring_path.is_file():
            return HealthCheckResult(
                name="policy_update_material",
                status="warning",
                message="policy_updates.public_keyring_file does not exist",
                details={"public_keyring_file": str(keyring_path)},
            )

    return HealthCheckResult(
        name="policy_update_material",
        status="ok",
        message="Policy update material is healthy",
        details={
            "private_key_file": str(secret_path),
            "public_keyring_file": str(keyring_path) if keyring_path else None,
        },
    )


def _check_api_bind(config: AppConfig) -> HealthCheckResult:
    api_cfg = config.api_config
    host = str(api_cfg.get("host", "127.0.0.1")).strip() or "127.0.0.1"
    port = int(api_cfg.get("port", 8765))
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((host, port))
        return HealthCheckResult(
            name="api_bind_check",
            status="ok",
            message="API host/port is available",
            details={"host": host, "port": port},
        )
    except OSError as error:
        return HealthCheckResult(
            name="api_bind_check",
            status="error",
            message="API host/port is unavailable",
            details={"host": host, "port": port, "error": str(error)},
        )
    finally:
        sock.close()


def _check_project_layout() -> HealthCheckResult:
    root = detect_project_root()
    required = [
        root / "src" / "arqon_guardian" / "cli.py",
        root / "scripts" / "run_agent.ps1",
        root / "dashboard" / "index.html",
        root / "config" / "default.yml",
    ]
    missing = [str(path) for path in required if not path.exists()]
    if missing:
        return HealthCheckResult(
            name="project_layout",
            status="warning",
            message="Project layout is incomplete",
            details={"missing": missing},
        )
    return HealthCheckResult(
        name="project_layout",
        status="ok",
        message="Project layout is healthy",
        details={"root": str(root)},
    )
