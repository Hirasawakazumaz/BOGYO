"""Conflict gate for peers' patches: the real sandbox ConflictEvaluator, fail closed.

A peer's shared block is recorded as ``applied`` on our chain only when the local
:class:`~sentinel.patch.ConflictEvaluator` actually executed its sandbox checks and
every one passed. Anything else keeps the block ``shared`` (pending a human):

* the payload carries no patch content (``hardened``) or it fails ``hardened_sha256``,
* no checks are configured, or the evaluation was a dry-run (nothing was verified),
* any check failed, or the guard / evaluator refused (kill-switch, escalation, ...).

Checks always come from the local operator, never from the peer's payload, so a
peer can never make this node run commands.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Optional

from ..patch.evaluator import ConflictEvaluator
from ..patch.model import PatchCandidate
from .chain import Block


@dataclass(frozen=True)
class GateDecision:
    ok: bool
    reason: str
    dry_run: bool = False

    def __bool__(self) -> bool:  # usable wherever a bool conflict checker is expected
        return self.ok


def candidate_from_block(block: Block) -> Optional[PatchCandidate]:
    """Rebuild the patch candidate a block carries, or None if it carries none."""
    p = block.payload
    hardened = p.get("hardened")
    if not isinstance(hardened, str) or not hardened:
        return None
    return PatchCandidate(
        finding_id=str(p.get("finding") or block.hash[:16]),
        service=str(p.get("service") or block.domain),
        path=str(p.get("path") or ""),
        rationale=f"mesh patch from {p.get('author') or block.author}",
        original=str(p.get("original") or ""),
        hardened=hardened,
    )


class ConflictGate:
    """Callable conflict checker for :func:`sentinel.mesh.serve` / ``consider_apply``."""

    def __init__(
        self, evaluator: ConflictEvaluator, checks: Optional[list[tuple[str, list[str]]]] = None
    ) -> None:
        self.evaluator = evaluator
        self.checks = checks  # None -> the evaluator's sandbox defaults

    def check(self, block: Block) -> GateDecision:
        candidate = candidate_from_block(block)
        if candidate is None:
            return GateDecision(False, "no patch content in block; manual review required")
        want = block.payload.get("hardened_sha256")
        if want and hashlib.sha256(candidate.hardened.encode("utf-8")).hexdigest() != want:
            return GateDecision(False, "hardened_sha256 mismatch")
        try:
            ev = self.evaluator.evaluate(candidate, self.checks)
        except Exception as exc:  # noqa: BLE001 - any failure keeps the block unapplied
            return GateDecision(False, f"conflict-eval refused: {type(exc).__name__}: {exc}")
        if not ev.checks:
            return GateDecision(False, "no conflict checks configured; nothing verified", ev.dry_run)
        if ev.dry_run:
            return GateDecision(False, "dry-run: sandbox checks planned, not executed", True)
        if not ev.ok:
            return GateDecision(False, "conflicts: " + ", ".join(ev.conflicts()))
        return GateDecision(True, "sandbox conflict-eval passed")

    __call__ = check
