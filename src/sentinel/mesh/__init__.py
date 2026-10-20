"""Distributed parallel-patch mesh among the operator's OWN servers only.

Pieces:
- identity: machine-bound, passphrase-encrypted node key file (not an API key).
- ratchet: rolling-key authenticated channel (key changes every message from the
  exchanged ciphertext + time window; only the matching key is accepted).
- chain: signed, hash-linked patch blocks (a private blockchain of patches).
- node: ties them together — each node owns a patch domain, shares its patches,
  and applies peers' patches only after a conflict check passes.

Consent requires this be used only among servers the operator owns.
"""

from .identity import NodeIdentity, machine_fingerprint
from .ratchet import RatchetChannel, RatchetError, derive_root
from .chain import Block, PatchChain
from .node import MeshNode

__all__ = [
    "NodeIdentity", "machine_fingerprint",
    "RatchetChannel", "RatchetError", "derive_root",
    "Block", "PatchChain", "MeshNode",
]
