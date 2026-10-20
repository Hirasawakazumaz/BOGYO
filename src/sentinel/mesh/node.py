"""A mesh node: owns a patch domain, shares patches over the rolling-key channel,
and applies peers' patches only after a conflict check passes.

Transport is abstracted: this module provides the encode/ingest steps (used by an
in-memory loopback in tests and by a thin network layer in deployment). The
security-relevant logic — authenticated rolling-key messaging, signed chain, and
conflict-gated apply — lives here and is fully testable offline.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Callable, Optional

from .chain import Block, PatchChain
from .identity import NodeIdentity
from .ratchet import RatchetChannel, derive_root


@dataclass
class Peer:
    name: str
    ed25519_pub: bytes
    x25519_pub: bytes
    domain: str = ""


class MeshNode:
    def __init__(self, identity: NodeIdentity, domain: str, chain: Optional[PatchChain] = None,
                 window_seconds: int = 30) -> None:
        self.identity = identity
        self.domain = domain
        self.chain = chain or PatchChain()
        self.window = window_seconds
        self.peers: dict[str, Peer] = {}
        self.channels: dict[str, RatchetChannel] = {}

    def add_peer(self, name: str, ed25519_pub: bytes, x25519_pub: bytes, domain: str = "") -> None:
        self.peers[name] = Peer(name, ed25519_pub, x25519_pub, domain)

    def channel(self, peer_name: str) -> RatchetChannel:
        if peer_name not in self.channels:
            peer = self.peers[peer_name]
            self.channels[peer_name] = RatchetChannel(
                derive_root(self.identity, peer.x25519_pub), self.window
            )
        return self.channels[peer_name]

    # -- authoring ---------------------------------------------------------- #
    def propose(self, payload: dict) -> Block:
        """Create + append a 'shared' patch block authored by this node."""
        block = self.chain.make_block(self.identity, self.domain, payload, status="shared")
        self.chain.append(block)
        return block

    # -- transport steps (wrap with the rolling-key channel) ---------------- #
    def encode_for(self, peer_name: str, block: Block) -> dict:
        return self.channel(peer_name).encrypt_json(asdict(block), self.identity)

    def ingest(self, peer_name: str, msg: dict) -> Block:
        """Decrypt + verify a peer's shared block and add it to our chain."""
        peer = self.peers[peer_name]
        data = self.channel(peer_name).decrypt_json(msg, peer.ed25519_pub)
        block = Block(**data)
        if not block.verify():
            raise ValueError("received block failed signature/hash verification")
        # re-anchor onto our own head so the chain stays linked locally
        rebased = self.chain.make_block(self.identity, block.domain, {
            "shared_ref": block.hash, "author": block.author, **block.payload
        }, status="shared")
        self.chain.append(rebased)
        return rebased

    # -- conflict-gated apply ---------------------------------------------- #
    def consider_apply(self, shared_block: Block, conflict_checker: Callable[[Block], bool]) -> Optional[Block]:
        """Apply a shared patch only if the conflict check passes; records an ack block."""
        if not conflict_checker(shared_block):
            return None
        ack = self.chain.make_block(self.identity, shared_block.domain, {
            "applied_ref": shared_block.hash, **shared_block.payload
        }, status="applied")
        self.chain.append(ack)
        return ack
