"""A private, signed patch blockchain shared among the operator's nodes.

Each block records one proposed/verified patch, is signed by its author node,
and links to the previous block by hash. The chain lets nodes agree on the set
of patches and the order they were shared/applied, and makes tampering evident.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from .identity import NodeIdentity, verify_signature

GENESIS = "0" * 64


def _canon(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


@dataclass
class Block:
    index: int
    prev_hash: str
    ts: str
    author: str          # node name
    author_pub: str      # ed25519 pub hex
    domain: str          # patch domain (e.g. sshd)
    payload: dict        # {finding, service, path, hardened_sha256, rationale}
    status: str = "shared"   # "shared" -> "applied" (after conflict check)
    sig: str = ""
    hash: str = ""

    def body(self) -> dict:
        return {"index": self.index, "prev_hash": self.prev_hash, "ts": self.ts,
                "author": self.author, "author_pub": self.author_pub,
                "domain": self.domain, "payload": self.payload, "status": self.status}

    def compute_hash(self) -> str:
        return hashlib.sha256(_canon(self.body())).hexdigest()

    def sign(self, identity: NodeIdentity) -> "Block":
        self.hash = self.compute_hash()
        self.sig = identity.sign(self.hash.encode()).hex()
        return self

    def verify(self) -> bool:
        if self.hash != self.compute_hash():
            return False
        return verify_signature(bytes.fromhex(self.author_pub), self.hash.encode(), bytes.fromhex(self.sig))


class PatchChain:
    def __init__(self, path: Optional[str] = None) -> None:
        self.path = Path(path) if path else None
        self.blocks: list[Block] = []
        if self.path and self.path.exists():
            self._load()

    def _load(self) -> None:
        for line in self.path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line:
                self.blocks.append(Block(**json.loads(line)))

    def _persist(self) -> None:
        if not self.path:
            return
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("w", encoding="utf-8") as fh:
            for b in self.blocks:
                fh.write(json.dumps(asdict(b), ensure_ascii=False) + "\n")

    def head_hash(self) -> str:
        return self.blocks[-1].hash if self.blocks else GENESIS

    def height(self) -> int:
        return len(self.blocks)

    def make_block(self, identity: NodeIdentity, domain: str, payload: dict, status: str = "shared") -> Block:
        b = Block(index=len(self.blocks), prev_hash=self.head_hash(),
                  ts=datetime.now(timezone.utc).isoformat(), author=identity.name,
                  author_pub=identity.ed25519_pub_hex(), domain=domain, payload=payload, status=status)
        return b.sign(identity)

    def append(self, block: Block) -> None:
        """Append a block after validating link + signature (fail closed)."""
        if block.prev_hash != self.head_hash():
            raise ValueError("block does not link to current head")
        if block.index != len(self.blocks):
            raise ValueError("block index mismatch")
        if not block.verify():
            raise ValueError("block signature/hash invalid")
        self.blocks.append(block)
        self._persist()

    def validate(self) -> bool:
        prev = GENESIS
        for i, b in enumerate(self.blocks):
            if b.index != i or b.prev_hash != prev or not b.verify():
                return False
            prev = b.hash
        return True

    def pending(self) -> list[Block]:
        return [b for b in self.blocks if b.status == "shared"]

    def applied(self) -> list[Block]:
        return [b for b in self.blocks if b.status == "applied"]
