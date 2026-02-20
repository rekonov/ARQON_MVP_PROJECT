from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
from typing import Any

from arqon_guardian.crypto_signing import derive_public_key_pem, sign_ed25519, verify_ed25519


SCHEMA_ID = "arqon-update-pack@1"
DEFAULT_KEY_ID = "default"
DEFAULT_ARTIFACTS = [
    "src",
    "dashboard",
    "scripts",
    "browser-extension",
    "config",
    "pyproject.toml",
    "requirements.txt",
    "requirements-dev.txt",
    "README.md",
]
IGNORED_DIR_NAMES = {".git", ".venv", "__pycache__", ".pytest_cache", "state", "quarantine", "backups"}
IGNORED_FILE_SUFFIXES = {".pyc", ".pyo"}


class UpdatePackError(RuntimeError):
    pass


def build_manifest(source_root: Path, artifacts: list[str] | None = None) -> dict[str, Any]:
    root = source_root.resolve()
    if not root.exists() or not root.is_dir():
        raise UpdatePackError(f"Source root does not exist: {root}")

    selected = list(artifacts or DEFAULT_ARTIFACTS)
    file_entries: list[dict[str, Any]] = []
    missing_artifacts: list[str] = []

    for artifact in selected:
        normalized_artifact = _normalize_artifact_name(artifact)
        target = (root / normalized_artifact).resolve()
        if not _is_within_root(target, root):
            raise UpdatePackError(f"Artifact path escapes source root: {artifact}")
        if not target.exists():
            missing_artifacts.append(normalized_artifact)
            continue

        if target.is_file():
            file_entries.append(_file_entry(target, root))
            continue

        for file_path in _iter_files(target):
            file_entries.append(_file_entry(file_path, root))

    file_entries.sort(key=lambda item: str(item["path"]))

    total_size_bytes = sum(int(item["size_bytes"]) for item in file_entries)
    return {
        "source_root": str(root),
        "artifacts": selected,
        "generated_at_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "file_count": len(file_entries),
        "total_size_bytes": total_size_bytes,
        "missing_artifacts": sorted(missing_artifacts),
        "files": file_entries,
    }


def sign_update_pack(
    manifest: dict[str, Any],
    *,
    secret: str,
    issuer: str,
    version: str | None = None,
    key_id: str = DEFAULT_KEY_ID,
    notes: str | None = None,
) -> dict[str, Any]:
    if not isinstance(manifest, dict):
        raise UpdatePackError("Manifest must be an object")
    if not secret or not secret.strip():
        raise UpdatePackError("Signing secret cannot be empty")

    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    pack_version = version or datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
    normalized_key_id = key_id.strip() or DEFAULT_KEY_ID

    meta: dict[str, Any] = {
        "schema": SCHEMA_ID,
        "issuer": issuer.strip() or "arqon-release",
        "version": str(pack_version),
        "generated_at": generated_at,
        "file_count": int(manifest.get("file_count", 0)),
    }
    if notes:
        meta["notes"] = notes

    unsigned_pack = {"meta": meta, "manifest": manifest}
    signature = {
        "algorithm": "ed25519",
        "key_id": normalized_key_id,
        "value": _compute_signature(unsigned_pack, secret),
    }
    return {"meta": meta, "manifest": manifest, "signature": signature}


def verify_update_pack(
    pack: dict[str, Any],
    *,
    source_root: Path,
    secrets: dict[str, str] | str,
    strict_tree: bool = True,
) -> tuple[bool, str, dict[str, Any]]:
    if not isinstance(pack, dict):
        return False, "invalid_pack", {}

    meta = pack.get("meta")
    manifest = pack.get("manifest")
    signature = pack.get("signature")
    if not isinstance(meta, dict) or not isinstance(manifest, dict) or not isinstance(signature, dict):
        return False, "invalid_pack_structure", {}

    schema = str(meta.get("schema", "")).strip()
    if schema != SCHEMA_ID:
        return False, "unsupported_schema", {}

    algo = str(signature.get("algorithm", "")).strip().lower()
    key_id = str(signature.get("key_id", DEFAULT_KEY_ID)).strip() or DEFAULT_KEY_ID
    secrets_by_key = _normalize_secrets(secrets)
    selected_secret = secrets_by_key.get(key_id)
    if not selected_secret and key_id == DEFAULT_KEY_ID and len(secrets_by_key) == 1:
        selected_secret = next(iter(secrets_by_key.values()))
    if not selected_secret:
        return False, "unknown_key_id", {"key_id": key_id}

    provided = str(signature.get("value", "")).strip()
    if not provided:
        return False, "missing_signature_value", {}

    unsigned_pack = {"meta": meta, "manifest": manifest}
    if algo == "ed25519":
        try:
            public_key_pem = derive_public_key_pem(selected_secret)
        except Exception:
            return False, "invalid_verification_key", {}
        if not verify_ed25519(_canonical_json(unsigned_pack).encode("utf-8"), provided, public_key_pem):
            return False, "signature_mismatch", {}
    else:
        return False, "unsupported_signature_algorithm", {}

    version = str(meta.get("version", "")).strip()
    if not version:
        return False, "missing_version", {}

    artifacts_raw = manifest.get("artifacts", [])
    files_raw = manifest.get("files", [])
    if not isinstance(artifacts_raw, list) or not isinstance(files_raw, list):
        return False, "invalid_manifest", {}

    artifacts = [str(item).strip() for item in artifacts_raw if str(item).strip()]
    expected_entries: dict[str, dict[str, Any]] = {}
    for item in files_raw:
        if not isinstance(item, dict):
            return False, "invalid_manifest_file_entry", {}
        path_rel = str(item.get("path", "")).strip().replace("\\", "/")
        hash_value = str(item.get("sha256", "")).strip().lower()
        size_value = item.get("size_bytes")
        if not path_rel or not hash_value or not isinstance(size_value, int):
            return False, "invalid_manifest_file_entry", {}
        expected_entries[path_rel] = {"sha256": hash_value, "size_bytes": int(size_value)}

    root = source_root.resolve()
    if not root.exists() or not root.is_dir():
        return False, "source_root_missing", {"source_root": str(root)}

    actual_entries = _collect_entries_for_artifacts(root, artifacts)

    missing_paths = sorted(set(expected_entries) - set(actual_entries))
    extra_paths = sorted(set(actual_entries) - set(expected_entries))

    hash_mismatch: list[str] = []
    size_mismatch: list[str] = []
    for path_rel in sorted(set(expected_entries) & set(actual_entries)):
        expected_entry = expected_entries[path_rel]
        actual_entry = actual_entries[path_rel]
        if expected_entry["sha256"] != actual_entry["sha256"]:
            hash_mismatch.append(path_rel)
        if int(expected_entry["size_bytes"]) != int(actual_entry["size_bytes"]):
            size_mismatch.append(path_rel)

    if missing_paths:
        return False, "missing_files", {"count": len(missing_paths), "paths": missing_paths[:20]}
    if hash_mismatch:
        return False, "hash_mismatch", {"count": len(hash_mismatch), "paths": hash_mismatch[:20]}
    if size_mismatch:
        return False, "size_mismatch", {"count": len(size_mismatch), "paths": size_mismatch[:20]}
    if strict_tree and extra_paths:
        return False, "unexpected_files", {"count": len(extra_paths), "paths": extra_paths[:20]}

    file_count = int(manifest.get("file_count", len(expected_entries)))
    total_size_bytes = int(manifest.get("total_size_bytes", 0))
    return True, "ok", {
        "file_count": file_count,
        "total_size_bytes": total_size_bytes,
        "artifacts": artifacts,
    }


def save_update_pack(pack: dict[str, Any], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(pack, ensure_ascii=True, indent=2), encoding="utf-8")


def load_update_pack(path: Path) -> dict[str, Any]:
    if not path.exists():
        raise UpdatePackError(f"Update pack file not found: {path}")
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise UpdatePackError("Update pack payload must be an object")
    return payload


def _iter_files(root: Path):
    for item in root.rglob("*"):
        if not item.is_file():
            continue
        if any(part in IGNORED_DIR_NAMES for part in item.parts):
            continue
        if item.suffix.lower() in IGNORED_FILE_SUFFIXES:
            continue
        yield item


def _file_entry(path: Path, source_root: Path) -> dict[str, Any]:
    rel = path.resolve().relative_to(source_root.resolve()).as_posix()
    raw = path.read_bytes()
    sha256 = hashlib.sha256(raw).hexdigest()
    return {"path": rel, "sha256": sha256, "size_bytes": len(raw)}


def _normalize_artifact_name(value: str) -> str:
    normalized = str(value).strip().replace("\\", "/")
    if not normalized:
        raise UpdatePackError("Artifact name cannot be empty")
    return normalized


def _is_within_root(target: Path, root: Path) -> bool:
    try:
        target.relative_to(root.resolve())
        return True
    except ValueError:
        return False


def _normalize_secrets(secrets: dict[str, str] | str) -> dict[str, str]:
    if isinstance(secrets, str):
        if not secrets.strip():
            raise UpdatePackError("Update pack signing secret is empty")
        return {DEFAULT_KEY_ID: secrets.strip()}
    if isinstance(secrets, dict):
        output: dict[str, str] = {}
        for key, value in secrets.items():
            key_name = str(key).strip() or DEFAULT_KEY_ID
            if isinstance(value, str):
                secret_value = value.strip()
                if secret_value:
                    output[key_name] = secret_value
                continue
            if isinstance(value, dict):
                selected = (
                    str(value.get("private_key_pem", "")).strip()
                    or str(value.get("public_key_pem", "")).strip()
                    or str(value.get("secret", "")).strip()
                )
                if selected:
                    output[key_name] = selected
        if output:
            return output
    raise UpdatePackError("Update pack signing secrets are invalid")


def _compute_signature(unsigned_pack: dict[str, Any], secret: str) -> str:
    raw = _canonical_json(unsigned_pack).encode("utf-8")
    try:
        return sign_ed25519(raw, secret)
    except Exception as error:
        raise UpdatePackError(f"Failed to sign update pack: {error}") from error


def _canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=True, separators=(",", ":"), sort_keys=True)


def _collect_entries_for_artifacts(source_root: Path, artifacts: list[str]) -> dict[str, dict[str, Any]]:
    output: dict[str, dict[str, Any]] = {}
    for artifact in artifacts:
        target = (source_root / artifact).resolve()
        if not _is_within_root(target, source_root):
            raise UpdatePackError(f"Artifact path escapes source root: {artifact}")
        if not target.exists():
            continue
        if target.is_file():
            item = _file_entry(target, source_root)
            output[str(item["path"])] = item
            continue
        for file_path in _iter_files(target):
            item = _file_entry(file_path, source_root)
            output[str(item["path"])] = item
    return output
