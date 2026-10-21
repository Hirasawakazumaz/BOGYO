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
from .gate import ConflictGate, GateDecision
from .transport import make_server, push, serve

__all__ = [
    "NodeIdentity", "machine_fingerprint",
    "RatchetChannel", "RatchetError", "derive_root",
    "Block", "PatchChain", "MeshNode",
    "ConflictGate", "GateDecision",
    "serve", "push", "make_server",
]


def node_from_settings(settings, passphrase: str) -> MeshNode:
    """Build a MeshNode from a loaded Settings object + node key passphrase.

    Loads the machine-bound identity, attaches configured peers (hex pubs), and
    opens the persisted patch chain.
    """
    mc = settings.mesh
    identity = NodeIdentity.load(mc.key_file, passphrase)
    node = MeshNode(identity, mc.domain, PatchChain(mc.chain_file), mc.time_window_seconds)
    for p in mc.peers:
        if p.ed25519_pub and p.x25519_pub:
            node.add_peer(p.name, bytes.fromhex(p.ed25519_pub), bytes.fromhex(p.x25519_pub), p.domain)
    return node
