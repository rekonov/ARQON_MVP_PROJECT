from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import json
import logging
import os
from pathlib import Path
from typing import Any

try:
    import winreg
except ImportError:  # pragma: no cover - non-Windows fallback
    winreg = None


LOGGER = logging.getLogger(__name__)


@dataclass(slots=True)
class RegistrySetting:
    hive: str
    key_path: str
    value_name: str
    value_data: Any
    value_type_name: str


@dataclass(slots=True)
class BackupEntry:
    hive: str
    key_path: str
    value_name: str
    previous_exists: bool
    previous_value: Any
    previous_type_name: str | None
    new_value: Any
    new_type_name: str


PROFILE_DEFINITIONS: dict[str, list[RegistrySetting]] = {
    "telemetry_off": [
        RegistrySetting(
            hive="HKLM",
            key_path=r"SOFTWARE\Policies\Microsoft\Windows\DataCollection",
            value_name="AllowTelemetry",
            value_data=0,
            value_type_name="REG_DWORD",
        ),
        RegistrySetting(
            hive="HKCU",
            key_path=r"Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo",
            value_name="Enabled",
            value_data=0,
            value_type_name="REG_DWORD",
        ),
        RegistrySetting(
            hive="HKLM",
            key_path=r"SOFTWARE\Policies\Microsoft\Windows\CloudContent",
            value_name="DisableWindowsConsumerFeatures",
            value_data=1,
            value_type_name="REG_DWORD",
        ),
    ],
    "basic_anonymous": [
        RegistrySetting(
            hive="HKCU",
            key_path=r"Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager",
            value_name="SystemPaneSuggestionsEnabled",
            value_data=0,
            value_type_name="REG_DWORD",
        ),
        RegistrySetting(
            hive="HKCU",
            key_path=r"Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager",
            value_name="SubscribedContent-338388Enabled",
            value_data=0,
            value_type_name="REG_DWORD",
        ),
        RegistrySetting(
            hive="HKCU",
            key_path=r"Software\Microsoft\Windows\CurrentVersion\Privacy",
            value_name="TailoredExperiencesWithDiagnosticDataEnabled",
            value_data=0,
            value_type_name="REG_DWORD",
        ),
    ],
}


class HardeningManager:
    def __init__(self, state_dir: Path):
        self.state_dir = state_dir
        self.backup_dir = state_dir / "privacy-backups"
        self.backup_dir.mkdir(parents=True, exist_ok=True)

    def list_profiles(self) -> list[str]:
        return sorted(PROFILE_DEFINITIONS.keys())

    def apply_profile(self, profile_name: str) -> dict[str, Any]:
        _ensure_windows()
        settings = PROFILE_DEFINITIONS.get(profile_name)
        if settings is None:
            raise ValueError(f"Unknown profile: {profile_name}")

        timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        backup_entries: list[BackupEntry] = []
        applied = 0
        failed: list[dict[str, str]] = []

        for setting in settings:
            try:
                previous_value, previous_type_name, previous_exists = _read_registry_value(
                    setting.hive, setting.key_path, setting.value_name
                )
                _write_registry_value(
                    setting.hive,
                    setting.key_path,
                    setting.value_name,
                    setting.value_data,
                    setting.value_type_name,
                )
                backup_entries.append(
                    BackupEntry(
                        hive=setting.hive,
                        key_path=setting.key_path,
                        value_name=setting.value_name,
                        previous_exists=previous_exists,
                        previous_value=previous_value,
                        previous_type_name=previous_type_name,
                        new_value=setting.value_data,
                        new_type_name=setting.value_type_name,
                    )
                )
                applied += 1
            except PermissionError:
                failed.append(
                    {
                        "hive": setting.hive,
                        "key_path": setting.key_path,
                        "value_name": setting.value_name,
                        "error": "permission_denied",
                    }
                )
            except OSError as error:
                failed.append(
                    {
                        "hive": setting.hive,
                        "key_path": setting.key_path,
                        "value_name": setting.value_name,
                        "error": str(error),
                    }
                )

        backup_path = self.backup_dir / f"{timestamp}_{profile_name}.json"
        payload = {
            "timestamp_utc": timestamp,
            "profile_name": profile_name,
            "entries": [asdict(entry) for entry in backup_entries],
            "failed": failed,
        }
        backup_path.write_text(json.dumps(payload, ensure_ascii=True, indent=2), encoding="utf-8")

        LOGGER.info(
            "Privacy profile applied: %s (applied=%s failed=%s backup=%s)",
            profile_name,
            applied,
            len(failed),
            backup_path,
        )
        return {
            "profile_name": profile_name,
            "applied": applied,
            "failed": failed,
            "backup_file": str(backup_path),
        }

    def rollback(self, backup_file: Path | None = None) -> dict[str, Any]:
        _ensure_windows()
        target = backup_file or latest_backup_file(self.backup_dir)
        if target is None:
            raise FileNotFoundError("No privacy backup file found")

        payload = json.loads(target.read_text(encoding="utf-8"))
        entries = payload.get("entries", [])
        restored = 0
        failed: list[dict[str, str]] = []

        for entry in entries:
            hive = str(entry["hive"])
            key_path = str(entry["key_path"])
            value_name = str(entry["value_name"])
            previous_exists = bool(entry["previous_exists"])

            try:
                if previous_exists:
                    _write_registry_value(
                        hive,
                        key_path,
                        value_name,
                        entry.get("previous_value"),
                        str(entry.get("previous_type_name") or "REG_SZ"),
                    )
                else:
                    _delete_registry_value(hive, key_path, value_name)
                restored += 1
            except OSError as error:
                failed.append(
                    {
                        "hive": hive,
                        "key_path": key_path,
                        "value_name": value_name,
                        "error": str(error),
                    }
                )

        LOGGER.info(
            "Privacy rollback completed: backup=%s restored=%s failed=%s",
            target,
            restored,
            len(failed),
        )
        return {
            "backup_file": str(target),
            "restored": restored,
            "failed": failed,
        }


def latest_backup_file(backup_dir: Path) -> Path | None:
    candidates = sorted(backup_dir.glob("*.json"))
    if not candidates:
        return None
    return candidates[-1]


def _ensure_windows() -> None:
    if os.name != "nt" or winreg is None:
        raise RuntimeError("Windows registry hardening is supported only on Windows")


def _read_registry_value(hive: str, key_path: str, value_name: str) -> tuple[Any, str | None, bool]:
    hive_obj = _resolve_hive(hive)
    try:
        with winreg.OpenKey(hive_obj, key_path, 0, winreg.KEY_READ) as key:
            value, value_type = winreg.QueryValueEx(key, value_name)
            return value, _value_type_to_name(value_type), True
    except FileNotFoundError:
        return None, None, False


def _write_registry_value(
    hive: str,
    key_path: str,
    value_name: str,
    value_data: Any,
    value_type_name: str,
) -> None:
    hive_obj = _resolve_hive(hive)
    value_type = _name_to_value_type(value_type_name)
    with winreg.CreateKeyEx(hive_obj, key_path, 0, winreg.KEY_SET_VALUE) as key:
        winreg.SetValueEx(key, value_name, 0, value_type, value_data)


def _delete_registry_value(hive: str, key_path: str, value_name: str) -> None:
    hive_obj = _resolve_hive(hive)
    with winreg.CreateKeyEx(hive_obj, key_path, 0, winreg.KEY_SET_VALUE) as key:
        try:
            winreg.DeleteValue(key, value_name)
        except FileNotFoundError:
            return


def _resolve_hive(hive_name: str):
    mapping = {
        "HKCU": winreg.HKEY_CURRENT_USER,
        "HKLM": winreg.HKEY_LOCAL_MACHINE,
    }
    if hive_name not in mapping:
        raise ValueError(f"Unsupported hive: {hive_name}")
    return mapping[hive_name]


def _name_to_value_type(type_name: str) -> int:
    mapping = {
        "REG_DWORD": winreg.REG_DWORD,
        "REG_SZ": winreg.REG_SZ,
        "REG_QWORD": winreg.REG_QWORD,
    }
    if type_name not in mapping:
        raise ValueError(f"Unsupported registry type: {type_name}")
    return mapping[type_name]


def _value_type_to_name(value_type: int) -> str:
    mapping = {
        winreg.REG_DWORD: "REG_DWORD",
        winreg.REG_SZ: "REG_SZ",
        winreg.REG_QWORD: "REG_QWORD",
    }
    return mapping.get(value_type, "REG_SZ")

