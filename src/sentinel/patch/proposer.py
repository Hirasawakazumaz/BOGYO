"""PatchProposer — generate hardening candidates behind the guard.

Proposing a patch only produces *text* (a unified diff), so it is authorized as
``ActionClass.PATCH_PROPOSE``, which the guard permits whenever consent and scope
are valid. Nothing here touches a host.
"""

from __future__ import annotations

from ..core.actions import ActionClass
from ..guards import ScopeGuard
from .llm import PatchBackend, RuleBackend
from .model import Finding, PatchCandidate


class PatchProposer:
    def __init__(self, guard: ScopeGuard, backend: PatchBackend | None = None) -> None:
        self.guard = guard
        self.backend = backend or RuleBackend()

    def propose(self, finding: Finding) -> list[PatchCandidate]:
        self.guard.authorize(ActionClass.PATCH_PROPOSE)
        candidates = [c for c in self.backend.propose(finding) if not c.is_noop()]
        self.guard.audit.append(
            "patch.propose",
            {"finding": finding.id, "service": finding.service, "candidates": len(candidates)},
        )
        return candidates

    def refine(
        self, finding: Finding, candidate: PatchCandidate, conflicts: list[str]
    ) -> list[PatchCandidate]:
        self.guard.authorize(ActionClass.PATCH_PROPOSE)
        candidates = [c for c in self.backend.refine(finding, candidate, conflicts) if not c.is_noop()]
        self.guard.audit.append(
            "patch.refine",
            {"finding": finding.id, "conflicts": conflicts, "candidates": len(candidates)},
        )
        return candidates
