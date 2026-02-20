from __future__ import annotations

import base64
import ctypes
from ctypes import wintypes
import json
import os
from pathlib import Path
from typing import Any


class SecretStoreError(RuntimeError):
    pass


class SecretStore:
    def __init__(self, store_file: Path):
        self.store_file = store_file
        self.store_file.parent.mkdir(parents=True, exist_ok=True)
        self._provider = "dpapi" if os.name == "nt" else "plain"

    def get(self, key: str) -> str | None:
        payload = self._load_payload()
        item = payload.get("items", {}).get(key)
        if not isinstance(item, dict):
            return None
        encoded = str(item.get("value", "")).strip()
        if not encoded:
            return None
        raw = base64.b64decode(encoded.encode("ascii"))
        if payload.get("provider") == "dpapi":
            return _dpapi_decrypt(raw)
        return raw.decode("utf-8")

    def set(self, key: str, value: str) -> None:
        key_name = str(key).strip()
        if not key_name:
            raise SecretStoreError("Secret key cannot be empty")
        value_text = str(value).strip()
        if not value_text:
            raise SecretStoreError("Secret value cannot be empty")

        payload = self._load_payload()
        items = payload.setdefault("items", {})
        if not isinstance(items, dict):
            raise SecretStoreError("Secret store format is invalid")

        if payload.get("provider") == "dpapi":
            raw = _dpapi_encrypt(value_text)
        else:
            raw = value_text.encode("utf-8")
        items[key_name] = {"value": base64.b64encode(raw).decode("ascii")}
        self._save_payload(payload)

    def delete(self, key: str) -> bool:
        payload = self._load_payload()
        items = payload.get("items", {})
        if not isinstance(items, dict):
            return False
        if key not in items:
            return False
        del items[key]
        self._save_payload(payload)
        return True

    def list_keys(self) -> list[str]:
        payload = self._load_payload()
        items = payload.get("items", {})
        if not isinstance(items, dict):
            return []
        return sorted(str(item) for item in items.keys())

    def ensure(self) -> None:
        payload = self._load_payload()
        self._save_payload(payload)

    def _load_payload(self) -> dict[str, Any]:
        if not self.store_file.exists():
            return {"version": 1, "provider": self._provider, "items": {}}
        try:
            payload = json.loads(self.store_file.read_text(encoding="utf-8"))
        except json.JSONDecodeError as error:
            raise SecretStoreError(f"Invalid secret store file: {error}") from error
        if not isinstance(payload, dict):
            raise SecretStoreError("Secret store root must be object")
        provider = str(payload.get("provider", self._provider)).strip().lower()
        if provider not in {"dpapi", "plain"}:
            raise SecretStoreError(f"Unsupported secret store provider: {provider}")
        payload["provider"] = provider
        if "items" not in payload or not isinstance(payload["items"], dict):
            payload["items"] = {}
        if "version" not in payload:
            payload["version"] = 1
        return payload

    def _save_payload(self, payload: dict[str, Any]) -> None:
        self.store_file.write_text(json.dumps(payload, ensure_ascii=True, indent=2), encoding="utf-8")


class DATA_BLOB(ctypes.Structure):
    _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_byte))]


def _dpapi_encrypt(value: str) -> bytes:
    raw = value.encode("utf-8")
    in_buffer = ctypes.create_string_buffer(raw, len(raw))
    in_blob = DATA_BLOB(len(raw), ctypes.cast(in_buffer, ctypes.POINTER(ctypes.c_byte)))
    out_blob = DATA_BLOB()
    crypt32 = ctypes.windll.crypt32
    kernel32 = ctypes.windll.kernel32
    if not crypt32.CryptProtectData(
        ctypes.byref(in_blob),
        ctypes.c_wchar_p("ARQON Secret"),
        None,
        None,
        None,
        0,
        ctypes.byref(out_blob),
    ):
        raise SecretStoreError("DPAPI encryption failed")
    try:
        return ctypes.string_at(out_blob.pbData, out_blob.cbData)
    finally:
        kernel32.LocalFree(out_blob.pbData)


def _dpapi_decrypt(raw: bytes) -> str:
    in_buffer = ctypes.create_string_buffer(raw, len(raw))
    in_blob = DATA_BLOB(len(raw), ctypes.cast(in_buffer, ctypes.POINTER(ctypes.c_byte)))
    out_blob = DATA_BLOB()
    crypt32 = ctypes.windll.crypt32
    kernel32 = ctypes.windll.kernel32
    if not crypt32.CryptUnprotectData(
        ctypes.byref(in_blob),
        None,
        None,
        None,
        None,
        0,
        ctypes.byref(out_blob),
    ):
        raise SecretStoreError("DPAPI decryption failed")
    try:
        text = ctypes.string_at(out_blob.pbData, out_blob.cbData).decode("utf-8")
        return text
    finally:
        kernel32.LocalFree(out_blob.pbData)
