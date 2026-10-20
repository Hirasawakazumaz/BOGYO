"""Machine-bound, passphrase-encrypted node identity (Ed25519 sign + X25519 ECDH).

The private keys are stored encrypted with a key derived (scrypt) from the
operator passphrase AND a machine fingerprint. Copying the file to another
machine fails to decrypt (different fingerprint), so it is not a portable,
copyable secret like an API key. True hardware non-extraction (TPM/HSM) is out
of scope; this is machine+passphrase binding, and it is documented as such.
"""

from __future__ import annotations

import json
import os
import secrets
import socket
from dataclasses import dataclass
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, PublicFormat, NoEncryption

from ..core.errors import SigningError


def machine_fingerprint() -> bytes:
    """Stable per-machine bytes: /etc/machine-id (or hostname) — binds the key file."""
    for path in ("/etc/machine-id", "/var/lib/dbus/machine-id"):
        try:
            data = Path(path).read_text(encoding="utf-8").strip()
            if data:
                return data.encode()
        except OSError:
            continue
    return socket.gethostname().encode() or b"unknown-host"


def _derive(passphrase: str, salt: bytes) -> bytes:
    kdf = Scrypt(salt=salt + machine_fingerprint(), length=32, n=2**14, r=8, p=1)
    return kdf.derive(passphrase.encode("utf-8"))


@dataclass
class NodeIdentity:
    name: str
    _ed: Ed25519PrivateKey
    _x: X25519PrivateKey

    # -- construction ------------------------------------------------------- #
    @classmethod
    def create(cls, name: str) -> "NodeIdentity":
        return cls(name=name, _ed=Ed25519PrivateKey.generate(), _x=X25519PrivateKey.generate())

    # -- public material ---------------------------------------------------- #
    def ed25519_pub(self) -> bytes:
        return self._ed.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)

    def x25519_pub(self) -> bytes:
        return self._x.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)

    def ed25519_pub_hex(self) -> str:
        return self.ed25519_pub().hex()

    def x25519_pub_hex(self) -> str:
        return self.x25519_pub().hex()

    def sign(self, data: bytes) -> bytes:
        return self._ed.sign(data)

    def ecdh(self, peer_x25519_pub: bytes) -> bytes:
        return self._x.exchange(X25519PublicKey.from_public_bytes(peer_x25519_pub))

    # -- encrypted-at-rest, machine-bound ----------------------------------- #
    def save(self, path: str | Path, passphrase: str) -> None:
        if not passphrase:
            raise SigningError("a passphrase is required to protect the node key")
        salt = secrets.token_bytes(16)
        key = _derive(passphrase, salt)
        payload = json.dumps({
            "name": self.name,
            "ed": self._ed.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption()).hex(),
            "x": self._x.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption()).hex(),
        }).encode()
        nonce = secrets.token_bytes(12)
        ct = ChaCha20Poly1305(key).encrypt(nonce, payload, b"sentinel-mesh-node")
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps({"salt": salt.hex(), "nonce": nonce.hex(), "ct": ct.hex()}), encoding="utf-8")
        try:
            p.chmod(0o600)
        except OSError:
            pass

    @classmethod
    def load(cls, path: str | Path, passphrase: str) -> "NodeIdentity":
        blob = json.loads(Path(path).read_text(encoding="utf-8"))
        key = _derive(passphrase, bytes.fromhex(blob["salt"]))
        try:
            payload = ChaCha20Poly1305(key).decrypt(
                bytes.fromhex(blob["nonce"]), bytes.fromhex(blob["ct"]), b"sentinel-mesh-node"
            )
        except Exception as exc:  # noqa: BLE001 - wrong passphrase OR different machine
            raise SigningError(
                "cannot decrypt node key: wrong passphrase, or this file was created on another machine"
            ) from exc
        data = json.loads(payload)
        return cls(
            name=data["name"],
            _ed=Ed25519PrivateKey.from_private_bytes(bytes.fromhex(data["ed"])),
            _x=X25519PrivateKey.from_private_bytes(bytes.fromhex(data["x"])),
        )


def verify_signature(ed25519_pub: bytes, data: bytes, signature: bytes) -> bool:
    try:
        Ed25519PublicKey.from_public_bytes(ed25519_pub).verify(signature, data)
        return True
    except Exception:  # noqa: BLE001
        return False
