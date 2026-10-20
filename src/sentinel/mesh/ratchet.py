"""Rolling-key authenticated channel.

The session key changes on every message, derived from the *previous message's
ciphertext* and the current time window — so the key a peer must hold to be
accepted depends on the history of what was exchanged and on the clock. Each
message is encrypted in two AEAD layers and signed; if the key does not match,
AEAD authentication fails and the message is rejected. After a message is
processed, both sides ratchet the key forward identically.

This is a pragmatic, auditable construction built on vetted primitives
(X25519 + HKDF + ChaCha20-Poly1305 + Ed25519). It is not a formally-verified
Double Ratchet, and is intended for a trusted set of the operator's own nodes.
"""

from __future__ import annotations

import hashlib
import json
import secrets
import time
from dataclasses import dataclass

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .identity import NodeIdentity, verify_signature


class RatchetError(Exception):
    """Raised when a message fails authentication, ordering, or time checks."""


def _hkdf(key: bytes, info: bytes, length: int = 32) -> bytes:
    return HKDF(algorithm=SHA256(), length=length, salt=None, info=info).derive(key)


def derive_root(identity: NodeIdentity, peer_x25519_pub: bytes) -> bytes:
    """Shared root key for a node pair via X25519 ECDH (both sides compute the same)."""
    return _hkdf(identity.ecdh(peer_x25519_pub), b"sentinel-mesh-root")


@dataclass
class _Msg:
    n: int
    tw: int
    nonce1: str
    nonce2: str
    ct: str
    sig: str


class RatchetChannel:
    """One directional-symmetric ratchet state shared by a node pair.

    Messages must be processed in order. ``window_seconds`` sets the time
    granularity mixed into the key; a ±1 window skew is tolerated.
    """

    def __init__(self, root: bytes, window_seconds: int = 30) -> None:
        self._k = _hkdf(root, b"init")
        self._n = 0
        self.window = max(1, int(window_seconds))

    def _now_tw(self) -> int:
        return int(time.time() // self.window)

    def _layer_key(self, tw: int) -> bytes:
        return _hkdf(self._k, b"layer2:" + str(tw).encode())

    def _ratchet(self, ciphertext: bytes, tw: int) -> None:
        self._k = _hkdf(self._k, b"ratchet:" + hashlib.sha256(ciphertext).digest() + str(tw).encode())
        self._n += 1

    def encrypt(self, plaintext: bytes, identity: NodeIdentity) -> dict:
        tw = self._now_tw()
        aad = f"{self._n}:{tw}".encode()
        nonce1, nonce2 = secrets.token_bytes(12), secrets.token_bytes(12)
        layer1 = ChaCha20Poly1305(self._k).encrypt(nonce1, plaintext, aad)
        layer2 = ChaCha20Poly1305(self._layer_key(tw)).encrypt(nonce2, layer1, aad)
        sig = identity.sign(f"{self._n}:{tw}".encode() + layer2)
        msg = {"n": self._n, "tw": tw, "nonce1": nonce1.hex(), "nonce2": nonce2.hex(),
               "ct": layer2.hex(), "sig": sig.hex()}
        self._ratchet(layer2, tw)
        return msg

    def decrypt(self, msg: dict, peer_ed25519_pub: bytes) -> bytes:
        n, tw = int(msg["n"]), int(msg["tw"])
        if n != self._n:
            raise RatchetError(f"out-of-order message (expected {self._n}, got {n})")
        if abs(tw - self._now_tw()) > 1:
            raise RatchetError("message outside the accepted time window")
        layer2 = bytes.fromhex(msg["ct"])
        if not verify_signature(peer_ed25519_pub, f"{n}:{tw}".encode() + layer2, bytes.fromhex(msg["sig"])):
            raise RatchetError("signature verification failed")
        aad = f"{n}:{tw}".encode()
        try:
            layer1 = ChaCha20Poly1305(self._layer_key(tw)).decrypt(bytes.fromhex(msg["nonce2"]), layer2, aad)
            plaintext = ChaCha20Poly1305(self._k).decrypt(bytes.fromhex(msg["nonce1"]), layer1, aad)
        except Exception as exc:  # noqa: BLE001 - wrong/rolled key -> reject
            raise RatchetError("key mismatch — message rejected") from exc
        self._ratchet(layer2, tw)
        return plaintext

    # convenience for JSON payloads
    def encrypt_json(self, obj, identity: NodeIdentity) -> dict:
        return self.encrypt(json.dumps(obj, separators=(",", ":")).encode(), identity)

    def decrypt_json(self, msg: dict, peer_ed25519_pub: bytes):
        return json.loads(self.decrypt(msg, peer_ed25519_pub).decode())
