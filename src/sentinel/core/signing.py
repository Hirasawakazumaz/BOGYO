"""Ed25519 signing/verification and canonical hashing.

Used to sign the ownership scope and the operator consent record, and to seal the
audit log. Private keys never leave the operator's machine and are git-ignored.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from .errors import SigningError


def canonical_bytes(obj: Any) -> bytes:
    """Deterministic JSON encoding used as the signing/hashing input.

    Sorted keys, no insignificant whitespace, UTF-8. The same object always
    produces the same bytes, so signatures and hashes are reproducible.
    """
    return json.dumps(
        obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def generate_keypair(private_path: Path, public_path: Path) -> None:
    """Create an Ed25519 keypair. Refuses to overwrite an existing private key."""
    private_path = Path(private_path)
    public_path = Path(public_path)
    if private_path.exists():
        raise SigningError(f"refusing to overwrite existing private key: {private_path}")

    key = Ed25519PrivateKey.generate()
    priv_bytes = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub_bytes = key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    private_path.write_bytes(priv_bytes)
    try:
        private_path.chmod(0o600)
    except OSError:
        pass  # best effort on non-POSIX filesystems
    public_path.write_bytes(pub_bytes)


def load_private_key(path: Path) -> Ed25519PrivateKey:
    try:
        key = serialization.load_pem_private_key(Path(path).read_bytes(), password=None)
    except Exception as exc:  # noqa: BLE001 - re-raise as SigningError
        raise SigningError(f"cannot load private key {path}: {exc}") from exc
    if not isinstance(key, Ed25519PrivateKey):
        raise SigningError("private key is not Ed25519")
    return key


def load_public_key(path: Path) -> Ed25519PublicKey:
    try:
        key = serialization.load_pem_public_key(Path(path).read_bytes())
    except Exception as exc:  # noqa: BLE001
        raise SigningError(f"cannot load public key {path}: {exc}") from exc
    if not isinstance(key, Ed25519PublicKey):
        raise SigningError("public key is not Ed25519")
    return key


def sign(private_key: Ed25519PrivateKey, data: bytes) -> bytes:
    return private_key.sign(data)


def verify(public_key: Ed25519PublicKey, data: bytes, signature: bytes) -> None:
    """Verify a signature; raise :class:`SigningError` on any failure (fail-closed)."""
    try:
        public_key.verify(signature, data)
    except InvalidSignature as exc:
        raise SigningError("signature verification failed") from exc
