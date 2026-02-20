from __future__ import annotations

import base64
from dataclasses import dataclass

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)


@dataclass(frozen=True)
class KeyPair:
    private_key_pem: str
    public_key_pem: str


class SigningError(RuntimeError):
    pass


def generate_ed25519_keypair() -> KeyPair:
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")
    return KeyPair(private_key_pem=private_pem, public_key_pem=public_pem)


def sign_ed25519(message: bytes, private_key_pem: str) -> str:
    private_key = _load_private_key(private_key_pem)
    signature = private_key.sign(message)
    return base64.b64encode(signature).decode("ascii")


def verify_ed25519(message: bytes, signature_b64: str, public_key_pem: str) -> bool:
    public_key = _load_public_key(public_key_pem)
    try:
        signature = base64.b64decode(signature_b64.encode("ascii"), validate=True)
    except Exception as error:  # noqa: BLE001
        raise SigningError(f"Invalid signature encoding: {error}") from error
    try:
        public_key.verify(signature, message)
    except Exception:  # noqa: BLE001
        return False
    return True


def derive_public_key_pem(key_material_pem: str) -> str:
    text = str(key_material_pem or "").strip()
    if not text:
        raise SigningError("Key material is empty")
    if "BEGIN PUBLIC KEY" in text:
        _ = _load_public_key(text)
        return text
    private_key = _load_private_key(text)
    public_key = private_key.public_key()
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")


def is_private_key_pem(value: str) -> bool:
    return "BEGIN PRIVATE KEY" in str(value or "")


def is_public_key_pem(value: str) -> bool:
    return "BEGIN PUBLIC KEY" in str(value or "")


def _load_private_key(pem_text: str) -> Ed25519PrivateKey:
    text = str(pem_text or "").strip()
    if not text:
        raise SigningError("Private key is empty")
    try:
        key = serialization.load_pem_private_key(text.encode("utf-8"), password=None)
    except Exception as error:  # noqa: BLE001
        raise SigningError(f"Invalid private key PEM: {error}") from error
    if not isinstance(key, Ed25519PrivateKey):
        raise SigningError("Private key must be Ed25519")
    return key


def _load_public_key(pem_text: str) -> Ed25519PublicKey:
    text = str(pem_text or "").strip()
    if not text:
        raise SigningError("Public key is empty")
    try:
        key = serialization.load_pem_public_key(text.encode("utf-8"))
    except Exception as error:  # noqa: BLE001
        raise SigningError(f"Invalid public key PEM: {error}") from error
    if not isinstance(key, Ed25519PublicKey):
        raise SigningError("Public key must be Ed25519")
    return key
