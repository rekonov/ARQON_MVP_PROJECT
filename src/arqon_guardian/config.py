from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
import os
from pathlib import Path
import re
from typing import Any

import yaml

from arqon_guardian.secret_store import SecretStore


DEFAULT_CONFIG: dict[str, Any] = {
    "agent": {
        "poll_interval_sec": 2.0,
        "startup_firewall_sync": True,
    },
    "paths": {
        "downloads_dir": r"%USERPROFILE%\Downloads",
        "quarantine_dir": "./quarantine",
        "state_dir": "./state",
        "log_file": "./state/agent.log",
    },
    "monitoring": {
        "process_monitor": True,
        "download_monitor": True,
    },
    "watchdog": {
        "enabled": True,
        "check_interval_sec": 2.0,
        "max_restart_attempts": 3,
    },
    "rules": {
        "blocked_process_names": ["xmrig.exe", "mimikatz.exe", "processhacker.exe"],
        "lolbin_process_names": [
            "powershell.exe",
            "pwsh.exe",
            "cmd.exe",
            "mshta.exe",
            "rundll32.exe",
            "regsvr32.exe",
            "wscript.exe",
            "cscript.exe",
            "wmic.exe",
            "certutil.exe",
            "bitsadmin.exe",
            "msbuild.exe",
        ],
        "suspicious_cmdline_patterns": [
            r"(?i)(-enc|--encodedcommand)\s+[a-z0-9+/=]{20,}",
            r"(?i)(downloadstring|invoke-webrequest|iwr|curl)\b",
            r"(?i)(frombase64string|iex|invoke-expression)\b",
            r"(?i)(-windowstyle\s+hidden|-w\s+hidden)\b",
            r"(?i)\b(bypass|unrestricted)\b",
        ],
        "blocked_extensions": [
            ".scr",
            ".pif",
            ".hta",
            ".js",
            ".jse",
            ".vbs",
            ".vbe",
            ".wsf",
            ".bat",
            ".cmd",
            ".ps1",
            ".lnk",
        ],
        "blocked_hashes": [],
        "allowed_hashes": [],
        "archive_scan_enabled": True,
        "archive_scan_max_entries": 256,
        "archive_scan_max_total_uncompressed_mb": 128,
        "script_analysis_enabled": True,
        "script_analysis_max_bytes": 262_144,
        "suspicious_script_patterns": [
            r"(?i)invoke-webrequest|downloadstring|webclient",
            r"(?i)frombase64string|encodedcommand|-enc\b",
            r"(?i)iex\s*\(|invoke-expression",
            r"(?i)set-mppreference|add-mppreference",
            r"(?i)reg\s+add\s+.*\\run\b|schtasks(\.exe)?\s+/create",
            r"(?i)rundll32|regsvr32|mshta",
        ],
        "suspicious_name_patterns": [
            r"(?i)invoice.*\.(zip|rar|7z|exe)$",
            r"(?i)payment.*\.(exe|scr|hta)$",
        ],
        "blocked_url_patterns": [r"(?i)https?://[^/]*\.onion"],
        "suspicious_url_patterns": [
            r"(?i)(login|verify|wallet|seed|password).*(update|security|support)",
            r"(?i)(free|bonus|airdrop).*(claim|gift)",
        ],
        "high_risk_download_extensions": [".exe", ".msi", ".scr", ".hta", ".ps1"],
    },
    "network": {
        "blocked_hosts": [],
        "firewall_rule_prefix": "ARQON_GUARD_BLOCK_",
    },
    "api": {
        "enabled": True,
        "host": "127.0.0.1",
        "port": 8765,
        "auth_key": "",
        "auth_key_ref": "api_user_key",
        "admin_key": "",
        "admin_key_ref": "api_admin_key",
        "body_limit_bytes": 65536,
        "rate_limit_enabled": True,
        "rate_limit_requests": 120,
        "rate_limit_window_sec": 60,
        "admin_rate_limit_requests": 80,
    },
    "privacy": {
        "available_profiles": ["telemetry_off", "basic_anonymous"],
    },
    "reputation": {
        "enabled": True,
        "provider": "local",
        "timeout_sec": 2.5,
        "local": {
            "blocked_domains": [],
            "trusted_domains": [],
            "suspicious_keywords": [],
        },
        "remote": {
            "enabled": False,
            "endpoint": "",
            "api_key": "",
        },
        "cache": {
            "enabled": True,
            "ttl_sec": 900,
            "max_entries": 4096,
        },
    },
    "risk": {
        "block_threshold": 70,
        "warn_threshold": 40,
    },
    "policy_updates": {
        "enabled": False,
        "url": "",
        "interval_sec": 1800,
        "apply_on_startup": True,
        "private_key_file": "./config/policy-signing-private.pem",
        "public_keyring_file": "./config/policy-signing-public.keys.json",
        "secret_file": "",
        "keyring_file": "./config/policy-signing.keys.json",
    },
    "secrets": {
        "store_file": "./state/secure-secrets.json",
    },
    "retention": {
        "enabled": True,
        "interval_sec": 3600,
        "max_event_lines": 20000,
        "max_audit_lines": 20000,
        "max_quarantine_log_lines": 10000,
        "max_quarantine_files": 500,
        "max_quarantine_age_days": 30,
        "max_update_backups": 20,
        "max_policy_backups": 120,
        "max_privacy_backups": 120,
    },
}


class ConfigValidationError(ValueError):
    pass


def detect_project_root() -> Path:
    return Path(__file__).resolve().parents[2]


def _expand_path(value: object, base_dir: Path) -> Path:
    expanded = os.path.expandvars(os.path.expanduser(str(value)))
    as_path = Path(expanded)
    if not as_path.is_absolute():
        as_path = (base_dir / as_path).resolve()
    return as_path


def _deep_merge(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(base.get(key), dict):
            _deep_merge(base[key], value)
        else:
            base[key] = value
    return base


@dataclass(slots=True)
class AppConfig:
    data: dict[str, Any]
    config_path: Path

    @property
    def project_root(self) -> Path:
        return self.config_path.parent.parent.resolve()

    @property
    def path_base_dir(self) -> Path:
        # If config lives in "<project>/config/*.yml", keep relative paths at project root.
        parent = self.config_path.parent
        if parent.name.lower() == "config":
            return parent.parent.resolve()
        return parent.resolve()

    @property
    def poll_interval_sec(self) -> float:
        return float(self.data["agent"]["poll_interval_sec"])

    @property
    def startup_firewall_sync(self) -> bool:
        return bool(self.data["agent"]["startup_firewall_sync"])

    @property
    def downloads_dir(self) -> Path:
        return _expand_path(self.data["paths"]["downloads_dir"], self.path_base_dir)

    @property
    def quarantine_dir(self) -> Path:
        return _expand_path(self.data["paths"]["quarantine_dir"], self.path_base_dir)

    @property
    def state_dir(self) -> Path:
        return _expand_path(self.data["paths"]["state_dir"], self.path_base_dir)

    @property
    def log_file(self) -> Path:
        return _expand_path(self.data["paths"]["log_file"], self.path_base_dir)

    @property
    def process_monitor_enabled(self) -> bool:
        return bool(self.data["monitoring"]["process_monitor"])

    @property
    def download_monitor_enabled(self) -> bool:
        return bool(self.data["monitoring"]["download_monitor"])

    @property
    def watchdog_config(self) -> dict[str, Any]:
        return dict(self.data.get("watchdog", {}))

    @property
    def rules(self) -> dict[str, Any]:
        return self.data["rules"]

    @property
    def blocked_hosts(self) -> list[str]:
        return list(self.data["network"]["blocked_hosts"])

    @property
    def firewall_rule_prefix(self) -> str:
        return str(self.data["network"]["firewall_rule_prefix"])

    @property
    def api_config(self) -> dict[str, Any]:
        resolved = dict(self.data.get("api", {}))
        user_key = str(resolved.get("auth_key", "")).strip()
        admin_key = str(resolved.get("admin_key", "")).strip()
        auth_key_ref = str(resolved.get("auth_key_ref", "")).strip()
        admin_key_ref = str(resolved.get("admin_key_ref", "")).strip()

        if auth_key_ref and not user_key:
            try:
                store = SecretStore(self.secret_store_file)
                user_key = store.get(auth_key_ref) or ""
            except Exception:
                user_key = ""

        if admin_key_ref and not admin_key:
            try:
                store = SecretStore(self.secret_store_file)
                admin_key = store.get(admin_key_ref) or ""
            except Exception:
                admin_key = ""

        if not admin_key and user_key:
            admin_key = user_key

        resolved["auth_key"] = user_key
        resolved["admin_key"] = admin_key
        return resolved

    @property
    def secrets_config(self) -> dict[str, Any]:
        return dict(self.data.get("secrets", {}))

    @property
    def secret_store_file(self) -> Path:
        return _expand_path(self.secrets_config.get("store_file", "./state/secure-secrets.json"), self.path_base_dir)

    @property
    def retention_config(self) -> dict[str, Any]:
        return dict(self.data.get("retention", {}))

    @property
    def privacy_profiles(self) -> list[str]:
        return list(self.data["privacy"]["available_profiles"])

    @property
    def reputation_config(self) -> dict[str, Any]:
        return dict(self.data.get("reputation", {}))

    @property
    def risk_config(self) -> dict[str, Any]:
        return dict(self.data.get("risk", {}))

    @property
    def policy_updates_config(self) -> dict[str, Any]:
        return dict(self.data.get("policy_updates", {}))


def load_config(config_path: str | Path | None = None) -> AppConfig:
    project_root = detect_project_root()
    target = Path(config_path) if config_path else (project_root / "config" / "default.yml")
    target = target.resolve()
    if config_path is not None and not target.exists():
        raise ConfigValidationError(f"Configuration file not found: {target}")

    loaded: dict[str, Any] = {}
    if target.exists():
        raw = yaml.safe_load(target.read_text(encoding="utf-8"))
        if raw is None:
            loaded = {}
        elif isinstance(raw, dict):
            loaded = raw
        else:
            raise ConfigValidationError(
                f"Configuration root must be an object: {target}"
            )

    merged = _deep_merge(deepcopy(DEFAULT_CONFIG), loaded)
    errors = validate_config_data(merged)
    if errors:
        joined = "\n".join(f"- {item}" for item in errors)
        raise ConfigValidationError(f"Invalid configuration in {target}:\n{joined}")
    cfg = AppConfig(data=merged, config_path=target)

    cfg.state_dir.mkdir(parents=True, exist_ok=True)
    cfg.quarantine_dir.mkdir(parents=True, exist_ok=True)
    cfg.log_file.parent.mkdir(parents=True, exist_ok=True)
    cfg.secret_store_file.parent.mkdir(parents=True, exist_ok=True)

    return cfg


def validate_config_data(data: dict[str, Any]) -> list[str]:
    errors: list[str] = []

    agent = _as_dict(data, "agent", errors)
    api = _as_dict(data, "api", errors)
    rules = _as_dict(data, "rules", errors)
    risk = _as_dict(data, "risk", errors)
    policy_updates = _as_dict(data, "policy_updates", errors)
    reputation = _as_dict(data, "reputation", errors)
    watchdog = _as_dict(data, "watchdog", errors)
    secrets_cfg = _as_dict(data, "secrets", errors)
    retention = _as_dict(data, "retention", errors)

    _validate_number_range(
        agent,
        "poll_interval_sec",
        min_value=0.2,
        max_value=60.0,
        errors=errors,
        section="agent",
    )
    _validate_boolean(agent, "startup_firewall_sync", errors, section="agent")

    _validate_boolean(watchdog, "enabled", errors, section="watchdog")
    _validate_number_range(
        watchdog,
        "check_interval_sec",
        min_value=0.5,
        max_value=60.0,
        errors=errors,
        section="watchdog",
    )
    _validate_integer_range(watchdog, "max_restart_attempts", 1, 100, errors, section="watchdog")

    _validate_boolean(api, "enabled", errors, section="api")
    _validate_string(api, "host", errors, section="api", allow_empty=False)
    _validate_integer_range(api, "port", 1, 65535, errors, section="api")
    _validate_string(api, "auth_key", errors, section="api", allow_empty=True)
    _validate_string(api, "auth_key_ref", errors, section="api", allow_empty=True)
    _validate_string(api, "admin_key", errors, section="api", allow_empty=True)
    _validate_string(api, "admin_key_ref", errors, section="api", allow_empty=True)
    _validate_integer_range(api, "body_limit_bytes", 1024, 10 * 1024 * 1024, errors, section="api")
    _validate_boolean(api, "rate_limit_enabled", errors, section="api")
    _validate_integer_range(api, "rate_limit_requests", 1, 5000, errors, section="api")
    _validate_number_range(
        api,
        "rate_limit_window_sec",
        min_value=1.0,
        max_value=3600.0,
        errors=errors,
        section="api",
    )
    _validate_integer_range(api, "admin_rate_limit_requests", 1, 5000, errors, section="api")
    auth_key = str(api.get("auth_key", "")).strip()
    auth_key_ref = str(api.get("auth_key_ref", "")).strip()
    if not auth_key and not auth_key_ref:
        errors.append("api.auth_key or api.auth_key_ref must be provided")

    _validate_integer_range(risk, "block_threshold", 1, 100, errors, section="risk")
    _validate_integer_range(risk, "warn_threshold", 1, 100, errors, section="risk")
    block_threshold = risk.get("block_threshold")
    warn_threshold = risk.get("warn_threshold")
    if isinstance(block_threshold, int) and isinstance(warn_threshold, int):
        if warn_threshold > block_threshold:
            errors.append("risk.warn_threshold cannot be greater than risk.block_threshold")

    _validate_string_list(rules, "blocked_process_names", errors, section="rules")
    _validate_string_list(rules, "lolbin_process_names", errors, section="rules")
    _validate_string_list(rules, "suspicious_cmdline_patterns", errors, section="rules")
    _validate_string_list(rules, "blocked_extensions", errors, section="rules")
    _validate_string_list(rules, "blocked_hashes", errors, section="rules")
    _validate_string_list(rules, "allowed_hashes", errors, section="rules")
    _validate_string_list(rules, "high_risk_download_extensions", errors, section="rules")
    _validate_boolean(rules, "archive_scan_enabled", errors, section="rules")
    _validate_integer_range(rules, "archive_scan_max_entries", 1, 100_000, errors, section="rules")
    _validate_number_range(
        rules,
        "archive_scan_max_total_uncompressed_mb",
        min_value=1.0,
        max_value=10_240.0,
        errors=errors,
        section="rules",
    )
    _validate_boolean(rules, "script_analysis_enabled", errors, section="rules")
    _validate_integer_range(rules, "script_analysis_max_bytes", 256, 10 * 1024 * 1024, errors, section="rules")
    _validate_string_list(rules, "suspicious_script_patterns", errors, section="rules")
    _validate_string_list(rules, "suspicious_name_patterns", errors, section="rules")
    _validate_string_list(rules, "blocked_url_patterns", errors, section="rules")
    _validate_string_list(rules, "suspicious_url_patterns", errors, section="rules")
    _validate_regex_list(rules.get("suspicious_cmdline_patterns", []), "rules.suspicious_cmdline_patterns", errors)
    _validate_regex_list(rules.get("suspicious_script_patterns", []), "rules.suspicious_script_patterns", errors)
    _validate_regex_list(rules.get("suspicious_name_patterns", []), "rules.suspicious_name_patterns", errors)
    _validate_regex_list(rules.get("blocked_url_patterns", []), "rules.blocked_url_patterns", errors)
    _validate_regex_list(rules.get("suspicious_url_patterns", []), "rules.suspicious_url_patterns", errors)

    _validate_boolean(policy_updates, "enabled", errors, section="policy_updates")
    _validate_string(policy_updates, "url", errors, section="policy_updates", allow_empty=True)
    _validate_number_range(
        policy_updates,
        "interval_sec",
        min_value=30.0,
        max_value=86400.0,
        errors=errors,
        section="policy_updates",
    )
    _validate_boolean(policy_updates, "apply_on_startup", errors, section="policy_updates")
    _validate_string(policy_updates, "private_key_file", errors, section="policy_updates", allow_empty=True)
    _validate_string(policy_updates, "public_keyring_file", errors, section="policy_updates", allow_empty=True)
    _validate_string(policy_updates, "secret_file", errors, section="policy_updates", allow_empty=True)
    _validate_string(policy_updates, "keyring_file", errors, section="policy_updates", allow_empty=True)
    if bool(policy_updates.get("enabled")) and not str(policy_updates.get("url", "")).strip():
        errors.append("policy_updates.url is required when policy_updates.enabled=true")
    if bool(policy_updates.get("enabled")):
        private_path = str(policy_updates.get("private_key_file", "")).strip()
        legacy_secret = str(policy_updates.get("secret_file", "")).strip()
        if not private_path and not legacy_secret:
            errors.append("policy_updates.private_key_file is required when policy_updates.enabled=true")

    _validate_boolean(reputation, "enabled", errors, section="reputation")
    provider = str(reputation.get("provider", "")).strip().lower()
    if provider not in {"local", "remote", "hybrid"}:
        errors.append("reputation.provider must be one of: local, remote, hybrid")
    _validate_number_range(
        reputation,
        "timeout_sec",
        min_value=0.2,
        max_value=30.0,
        errors=errors,
        section="reputation",
    )
    cache = _as_dict(reputation, "cache", errors)
    _validate_boolean(cache, "enabled", errors, section="reputation.cache")
    _validate_number_range(
        cache,
        "ttl_sec",
        min_value=1.0,
        max_value=86_400.0,
        errors=errors,
        section="reputation.cache",
    )
    _validate_integer_range(cache, "max_entries", 1, 100_000, errors, section="reputation.cache")

    _validate_string(secrets_cfg, "store_file", errors, section="secrets", allow_empty=False)

    _validate_boolean(retention, "enabled", errors, section="retention")
    _validate_number_range(
        retention,
        "interval_sec",
        min_value=60.0,
        max_value=86_400.0,
        errors=errors,
        section="retention",
    )
    _validate_integer_range(retention, "max_event_lines", 100, 1_000_000, errors, section="retention")
    _validate_integer_range(retention, "max_audit_lines", 100, 1_000_000, errors, section="retention")
    _validate_integer_range(retention, "max_quarantine_log_lines", 100, 1_000_000, errors, section="retention")
    _validate_integer_range(retention, "max_quarantine_files", 50, 100_000, errors, section="retention")
    _validate_number_range(
        retention,
        "max_quarantine_age_days",
        min_value=1.0,
        max_value=3650.0,
        errors=errors,
        section="retention",
    )
    _validate_integer_range(retention, "max_update_backups", 1, 10000, errors, section="retention")
    _validate_integer_range(retention, "max_policy_backups", 10, 10000, errors, section="retention")
    _validate_integer_range(retention, "max_privacy_backups", 10, 10000, errors, section="retention")

    return errors


def _as_dict(source: dict[str, Any], key: str, errors: list[str]) -> dict[str, Any]:
    value = source.get(key)
    if isinstance(value, dict):
        return value
    errors.append(f"{key} must be an object")
    return {}


def _validate_string(
    section_data: dict[str, Any],
    key: str,
    errors: list[str],
    *,
    section: str,
    allow_empty: bool,
) -> None:
    value = section_data.get(key)
    if not isinstance(value, str):
        errors.append(f"{section}.{key} must be a string")
        return
    if not allow_empty and not value.strip():
        errors.append(f"{section}.{key} cannot be empty")


def _validate_boolean(
    section_data: dict[str, Any],
    key: str,
    errors: list[str],
    *,
    section: str,
) -> None:
    if not isinstance(section_data.get(key), bool):
        errors.append(f"{section}.{key} must be a boolean")


def _validate_integer_range(
    section_data: dict[str, Any],
    key: str,
    min_value: int,
    max_value: int,
    errors: list[str],
    *,
    section: str,
) -> None:
    value = section_data.get(key)
    if not isinstance(value, int):
        errors.append(f"{section}.{key} must be an integer")
        return
    if value < min_value or value > max_value:
        errors.append(f"{section}.{key} must be in range [{min_value}, {max_value}]")


def _validate_number_range(
    section_data: dict[str, Any],
    key: str,
    min_value: float,
    max_value: float,
    errors: list[str],
    *,
    section: str,
) -> None:
    value = section_data.get(key)
    if not isinstance(value, (int, float)):
        errors.append(f"{section}.{key} must be a number")
        return
    value_float = float(value)
    if value_float < min_value or value_float > max_value:
        errors.append(f"{section}.{key} must be in range [{min_value}, {max_value}]")


def _validate_string_list(
    section_data: dict[str, Any],
    key: str,
    errors: list[str],
    *,
    section: str,
) -> None:
    value = section_data.get(key)
    if not isinstance(value, list):
        errors.append(f"{section}.{key} must be a list")
        return
    for index, item in enumerate(value):
        if not isinstance(item, str):
            errors.append(f"{section}.{key}[{index}] must be a string")


def _validate_regex_list(values: Any, key: str, errors: list[str]) -> None:
    if not isinstance(values, list):
        return
    for index, pattern in enumerate(values):
        if not isinstance(pattern, str):
            continue
        try:
            re.compile(pattern)
        except re.error:
            errors.append(f"{key}[{index}] is not a valid regex")
