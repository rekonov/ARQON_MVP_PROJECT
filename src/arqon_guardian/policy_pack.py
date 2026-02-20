from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import hmac
import json
from pathlib import Path
import re
import tempfile
from typing import Any
from urllib import request

import yaml

from arqon_guardian.crypto_signing import derive_public_key_pem, sign_ed25519, verify_ed25519


SCHEMA_ID = "arqon-policy-pack@1"
DEFAULT_KEY_ID = "default"
ALLOWED_POLICY_ROOTS = {"rules", "network", "risk", "reputation"}


class PolicyPackError(RuntimeError):
    pass


def sign_policy_pack(
    policy_data: dict[str, Any],
    secret: str,
    issuer: str,
    version: str | None = None,
    notes: str | None = None,
    key_id: str = DEFAULT_KEY_ID,
) -> dict[str, Any]:
    if not isinstance(policy_data, dict):
        raise PolicyPackError("Policy payload must be a JSON object")
    if not secret or not secret.strip():
        raise PolicyPackError("Signing key cannot be empty")

    filtered_policy = _filter_policy(policy_data)
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    pack_version = version or datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
    normalized_key_id = key_id.strip() or DEFAULT_KEY_ID

    meta: dict[str, Any] = {
        "schema": SCHEMA_ID,
        "issuer": issuer.strip() or "arqon",
        "version": str(pack_version),
        "generated_at": timestamp,
    }
    if notes:
        meta["notes"] = notes

    unsigned_pack = {"meta": meta, "policy": filtered_policy}
    signature_value = _compute_signature(unsigned_pack, secret)
    return {
        "meta": meta,
        "policy": filtered_policy,
        "signature": {
            "algorithm": "ed25519",
            "key_id": normalized_key_id,
            "value": signature_value,
        },
    }


def verify_policy_pack(
    pack: dict[str, Any],
    secrets: dict[str, str] | str,
) -> tuple[bool, str]:
    if not isinstance(pack, dict):
        return False, "invalid_pack"

    meta = pack.get("meta")
    policy = pack.get("policy")
    signature = pack.get("signature")
    if not isinstance(meta, dict) or not isinstance(policy, dict) or not isinstance(signature, dict):
        return False, "invalid_pack_structure"

    schema = str(meta.get("schema", "")).strip()
    if schema != SCHEMA_ID:
        return False, "unsupported_schema"

    algo = str(signature.get("algorithm", "")).strip().lower()
    key_id = str(signature.get("key_id", DEFAULT_KEY_ID)).strip() or DEFAULT_KEY_ID
    secrets_by_key = _normalize_secrets(secrets)
    selected_secret = secrets_by_key.get(key_id)
    if not selected_secret and key_id == DEFAULT_KEY_ID and len(secrets_by_key) == 1:
        selected_secret = next(iter(secrets_by_key.values()))
    if not selected_secret:
        return False, "unknown_key_id"

    provided = str(signature.get("value", "")).strip()
    if not provided:
        return False, "missing_signature_value"

    unsigned_pack = {"meta": meta, "policy": policy}
    if algo == "ed25519":
        try:
            public_key_pem = derive_public_key_pem(selected_secret)
        except Exception:
            return False, "invalid_verification_key"
        if not verify_ed25519(_canonical_json(unsigned_pack).encode("utf-8"), provided, public_key_pem):
            return False, "signature_mismatch"
    elif algo == "hmac-sha256":
        # Legacy compatibility path.
        expected = _compute_hmac_signature(unsigned_pack, selected_secret)
        if not hmac.compare_digest(expected, provided.lower()):
            return False, "signature_mismatch"
    else:
        return False, "unsupported_signature_algorithm"

    version = str(meta.get("version", "")).strip()
    if not version:
        return False, "missing_version"

    return True, "ok"


def apply_policy_pack(
    pack: dict[str, Any],
    config_path: Path,
    secrets: dict[str, str] | str,
    state_dir: Path,
    *,
    enforce_monotonic_version: bool = True,
    allow_replay: bool = False,
) -> dict[str, Any]:
    ok, reason = verify_policy_pack(pack, secrets)
    if not ok:
        raise PolicyPackError(f"Policy verification failed: {reason}")

    policy = pack.get("policy", {})
    if not isinstance(policy, dict):
        raise PolicyPackError("Policy payload is invalid")

    if not config_path.exists():
        raise PolicyPackError(f"Config file not found: {config_path}")

    meta = pack.get("meta", {})
    signature = pack.get("signature", {})
    issuer = str(meta.get("issuer", "")).strip() or "unknown"
    version = str(meta.get("version", "")).strip()
    key_id = str(signature.get("key_id", DEFAULT_KEY_ID)).strip() or DEFAULT_KEY_ID

    current_state = _load_version_state(state_dir)
    scope = f"{issuer}:{key_id}"
    previous_version = str(current_state.get(scope, "")).strip()
    if enforce_monotonic_version and not allow_replay and previous_version:
        relation = compare_policy_versions(version, previous_version)
        if relation <= 0:
            raise PolicyPackError(
                f"Policy replay/rollback rejected for scope={scope}: "
                f"incoming={version} current={previous_version}"
            )

    current = _load_data_file(config_path)
    if not isinstance(current, dict):
        current = {}

    backup_dir = state_dir / "policy-backups"
    backup_dir.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    backup_file = backup_dir / f"{timestamp}_{config_path.name}"
    backup_file.write_text(config_path.read_text(encoding="utf-8"), encoding="utf-8")

    merged = _deep_merge(dict(current), _filter_policy(policy))
    config_path.write_text(yaml.safe_dump(merged, sort_keys=False), encoding="utf-8")

    current_state[scope] = version
    _save_version_state(state_dir, current_state)

    history_file = state_dir / "policy-history.jsonl"
    history_entry = {
        "timestamp_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "version": version,
        "issuer": issuer,
        "key_id": key_id,
        "config_path": str(config_path),
        "backup_file": str(backup_file),
        "scope": scope,
    }
    with history_file.open("a", encoding="utf-8") as stream:
        stream.write(json.dumps(history_entry, ensure_ascii=True))
        stream.write("\n")

    return {
        "applied": True,
        "version": version,
        "issuer": issuer,
        "key_id": key_id,
        "scope": scope,
        "backup_file": str(backup_file),
        "config_path": str(config_path),
    }


def pull_policy_pack(url: str, timeout_sec: float = 5.0) -> dict[str, Any]:
    req = request.Request(url=url, method="GET")
    with request.urlopen(req, timeout=max(0.5, timeout_sec)) as response:
        raw = response.read().decode("utf-8", errors="replace")
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as error:
        raise PolicyPackError(f"Invalid pack JSON: {error}") from error
    if not isinstance(payload, dict):
        raise PolicyPackError("Policy pack payload must be an object")
    return payload


def read_secrets(
    *,
    secret: str | None = None,
    secret_file: Path | None = None,
    keyring_file: Path | None = None,
) -> dict[str, str]:
    keys: dict[str, str] = {}

    if keyring_file and keyring_file.exists():
        payload = _load_data_file(keyring_file)
        _merge_keyring_payload(keys, payload)

    if secret and secret.strip():
        keys[DEFAULT_KEY_ID] = secret.strip()
    elif secret_file and secret_file.exists():
        if secret_file.suffix.lower() in {".json", ".yml", ".yaml"}:
            payload = _load_data_file(secret_file)
            _merge_keyring_payload(keys, payload)
        else:
            value = secret_file.read_text(encoding="utf-8").strip()
            if value:
                keys[DEFAULT_KEY_ID] = value

    if not keys:
        raise PolicyPackError("Policy signing keys are not provided")
    return keys


def read_secret(secret: str | None = None, secret_file: Path | None = None) -> str:
    keys = read_secrets(secret=secret, secret_file=secret_file, keyring_file=None)
    return next(iter(keys.values()))


def load_policy_source(path: Path) -> dict[str, Any]:
    payload = _load_data_file(path)
    if not isinstance(payload, dict):
        raise PolicyPackError(f"Policy source must be an object: {path}")

    if "policy" in payload and isinstance(payload.get("policy"), dict):
        return dict(payload["policy"])
    return payload


def save_policy_pack(pack: dict[str, Any], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(pack, ensure_ascii=True, indent=2), encoding="utf-8")


def load_policy_pack(path: Path) -> dict[str, Any]:
    payload = _load_data_file(path)
    if not isinstance(payload, dict):
        raise PolicyPackError(f"Policy pack must be an object: {path}")
    return payload


def compare_policy_versions(candidate: str, current: str) -> int:
    c = (candidate or "").strip()
    p = (current or "").strip()
    if c == p:
        return 0

    parsed_candidate = _parse_version(c)
    parsed_current = _parse_version(p)

    if parsed_candidate[0] == parsed_current[0]:
        return _compare_parsed_version(parsed_candidate, parsed_current)

    return 1 if c > p else -1


def _parse_version(value: str) -> tuple[str, Any]:
    if re.fullmatch(r"\d{8,20}", value):
        return "timestamp", int(value)
    if re.fullmatch(r"\d+(\.\d+)+", value):
        return "segments", tuple(int(item) for item in value.split("."))
    return "string", value


def _compare_parsed_version(left: tuple[str, Any], right: tuple[str, Any]) -> int:
    _, lv = left
    _, rv = right
    if lv == rv:
        return 0
    return 1 if lv > rv else -1


def _normalize_secrets(secrets: dict[str, str] | str) -> dict[str, str]:
    if isinstance(secrets, str):
        if not secrets.strip():
            raise PolicyPackError("Policy signing key is empty")
        return {DEFAULT_KEY_ID: secrets.strip()}
    if isinstance(secrets, dict):
        normalized: dict[str, str] = {}
        for key, value in secrets.items():
            key_name = str(key).strip() or DEFAULT_KEY_ID
            if isinstance(value, str):
                val = value.strip()
                if val:
                    normalized[key_name] = val
                continue
            if isinstance(value, dict):
                selected = (
                    str(value.get("private_key_pem", "")).strip()
                    or str(value.get("public_key_pem", "")).strip()
                    or str(value.get("secret", "")).strip()
                )
                if selected:
                    normalized[key_name] = selected
        if normalized:
            return normalized
    raise PolicyPackError("Policy signing keys are invalid")


def _compute_signature(unsigned_pack: dict[str, Any], signing_key: str) -> str:
    message = _canonical_json(unsigned_pack).encode("utf-8")
    try:
        return sign_ed25519(message, signing_key)
    except Exception as error:
        raise PolicyPackError(f"Failed to sign policy pack: {error}") from error


def _compute_hmac_signature(unsigned_pack: dict[str, Any], secret: str) -> str:
    message = _canonical_json(unsigned_pack).encode("utf-8")
    digest = hmac.new(secret.encode("utf-8"), message, digestmod=hashlib.sha256)
    return digest.hexdigest()


def _canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=True, separators=(",", ":"), sort_keys=True)


def _filter_policy(policy_data: dict[str, Any]) -> dict[str, Any]:
    filtered: dict[str, Any] = {}
    for key in ALLOWED_POLICY_ROOTS:
        value = policy_data.get(key)
        if isinstance(value, dict):
            filtered[key] = value
    return filtered


def _deep_merge(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(base.get(key), dict):
            _deep_merge(base[key], value)
        else:
            base[key] = value
    return base


def _load_data_file(path: Path) -> Any:
    if not path.exists():
        raise PolicyPackError(f"File not found: {path}")

    raw = path.read_text(encoding="utf-8")
    suffix = path.suffix.lower()
    if suffix in {".yml", ".yaml"}:
        return yaml.safe_load(raw)
    return json.loads(raw)


def _merge_keyring_payload(target: dict[str, str], payload: Any) -> None:
    if not isinstance(payload, dict):
        raise PolicyPackError("Invalid keyring format: expected object")

    keys_value = payload.get("keys", payload)
    if isinstance(keys_value, dict):
        for key_id, key_data in keys_value.items():
            normalized_id = str(key_id).strip() or DEFAULT_KEY_ID
            if isinstance(key_data, str) and key_data.strip():
                target[normalized_id] = key_data.strip()
                continue
            if isinstance(key_data, dict):
                selected = (
                    str(key_data.get("private_key_pem", "")).strip()
                    or str(key_data.get("public_key_pem", "")).strip()
                    or str(key_data.get("secret", "")).strip()
                )
                if selected:
                    target[normalized_id] = selected
        return

    if isinstance(keys_value, list):
        for entry in keys_value:
            if not isinstance(entry, dict):
                continue
            key_id = str(entry.get("id", "")).strip() or DEFAULT_KEY_ID
            selected = (
                str(entry.get("private_key_pem", "")).strip()
                or str(entry.get("public_key_pem", "")).strip()
                or str(entry.get("secret", "")).strip()
            )
            if selected:
                target[key_id] = selected
        return

    raise PolicyPackError("Invalid keyring format: expected keys object or list")


def _load_version_state(state_dir: Path) -> dict[str, str]:
    file_path = state_dir / "policy-version-state.json"
    if not file_path.exists():
        return {}
    try:
        payload = json.loads(file_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return {}
    if not isinstance(payload, dict):
        return {}

    output: dict[str, str] = {}
    for key, value in payload.items():
        if isinstance(key, str) and isinstance(value, str):
            output[key] = value
    return output


def _save_version_state(state_dir: Path, versions: dict[str, str]) -> None:
    state_dir.mkdir(parents=True, exist_ok=True)
    file_path = state_dir / "policy-version-state.json"
    file_path.write_text(json.dumps(versions, ensure_ascii=True, indent=2), encoding="utf-8")


def pull_and_apply_policy_pack(
    url: str,
    config_path: Path,
    state_dir: Path,
    secrets: dict[str, str] | str,
    timeout_sec: float = 5.0,
) -> dict[str, Any]:
    pack = pull_policy_pack(url=url, timeout_sec=timeout_sec)
    return apply_policy_pack(
        pack=pack,
        config_path=config_path,
        secrets=secrets,
        state_dir=state_dir,
    )


def write_temp_pack(pack: dict[str, Any]) -> Path:
    with tempfile.NamedTemporaryFile(prefix="arqon-pack-", suffix=".json", delete=False) as tmp:
        tmp.write(json.dumps(pack, ensure_ascii=True).encode("utf-8"))
        return Path(tmp.name)
