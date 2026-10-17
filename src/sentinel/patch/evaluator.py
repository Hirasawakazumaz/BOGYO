"""ConflictEvaluator + propose->evaluate->refine loop, plus guarded host apply.

The evaluator applies a candidate inside the **sandbox replica** and runs checks
for service-startup, dependency, and performance regressions. This happens off
production, so it stays part of *proposing* a validated patch
(``ActionClass.PATCH_PROPOSE``) — it never mutates a real host.

Applying to a real host is the only step that uses ``ActionClass.PATCH_APPLY``:
it requires the ``enable_patch_apply`` toggle **and** explicit ``approved=True``
human approval (both enforced by the guard), and in dry-run it emits the unified
diff without writing anything.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from ..core.actions import ActionClass
from ..guards import ScopeGuard
from ..sandbox.replay import SandboxReplay, _assert_no_escalation
from .model import Finding, PatchCandidate


def _classify(name: str) -> str:
    n = name.lower()
    if "start" in n or "boot" in n or "restart" in n:
        return "startup"
    if "dep" in n or "require" in n:
        return "dependency"
    if "perf" in n or "bench" in n or "latency" in n:
        return "perf"
    return "other"


@dataclass(frozen=True)
class CheckResult:
    name: str
    kind: str
    command: list[str]
    dry_run: bool
    returncode: Optional[int] = None
    ok: bool = True


@dataclass(frozen=True)
class EvalResult:
    finding_id: str
    candidate: PatchCandidate
    checks: list[CheckResult]
    dry_run: bool

    @property
    def ok(self) -> bool:
        return all(c.ok for c in self.checks)

    def conflicts(self) -> list[str]:
        return [c.name for c in self.checks if not c.ok]


class ConflictEvaluator:
    """Apply a candidate in the sandbox and check for regressions/conflicts.

    ``checks`` is a list of ``(name, command)`` pairs run via the sandbox runner;
    a check passes when its command exits 0. If a :class:`SandboxReplay` is given
    and no checks are supplied, a default ``startup:restart`` check is derived.
    """

    def __init__(
        self,
        guard: ScopeGuard,
        *,
        sandbox: Optional[SandboxReplay] = None,
        runner=None,
    ) -> None:
        self.guard = guard
        self.sandbox = sandbox
        self._runner = runner or (sandbox._runner if sandbox is not None else SandboxReplay._default_runner)

    def _default_checks(self, candidate: PatchCandidate) -> list[tuple[str, list[str]]]:
        if self.sandbox is None:
            return []
        sb = self.sandbox
        if sb.compose_file is None:
            return []
        return [
            (
                "startup:restart",
                ["docker", "compose", "-p", sb.project, "-f", sb.compose_file, "restart", candidate.service],
            )
        ]

    def evaluate(
        self, candidate: PatchCandidate, checks: list[tuple[str, list[str]]] | None = None
    ) -> EvalResult:
        self.guard.authorize(ActionClass.PATCH_PROPOSE)  # still only a proposal; sandbox-only
        checks = checks if checks is not None else self._default_checks(candidate)
        for _, command in checks:
            _assert_no_escalation(command, "conflict-eval check")

        dry = self.guard.settings.dry_run
        results: list[CheckResult] = []
        for name, command in checks:
            kind = _classify(name)
            if dry:
                results.append(CheckResult(name, kind, command, dry_run=True, ok=True))
                continue
            rc, _ = self._runner(command)
            results.append(CheckResult(name, kind, command, dry_run=False, returncode=rc, ok=(rc == 0)))

        self.guard.audit.append(
            "patch.evaluate",
            {
                "finding": candidate.finding_id,
                "checks": [c.name for c in results],
                "conflicts": [c.name for c in results if not c.ok],
                "dry_run": dry,
            },
        )
        return EvalResult(candidate.finding_id, candidate, results, dry_run=dry)


@dataclass(frozen=True)
class LoopResult:
    finding_id: str
    accepted: bool
    rounds: int
    candidate: Optional[PatchCandidate]
    evaluation: Optional[EvalResult]


class PatchLoop:
    """Tie proposer + evaluator into a propose -> evaluate -> refine loop."""

    def __init__(self, proposer, evaluator: ConflictEvaluator) -> None:
        self.proposer = proposer
        self.evaluator = evaluator

    def run(
        self,
        finding: Finding,
        checks: list[tuple[str, list[str]]] | None = None,
        *,
        max_rounds: int = 3,
    ) -> LoopResult:
        candidate: Optional[PatchCandidate] = None
        evaluation: Optional[EvalResult] = None
        conflicts: list[str] = []
        for rnd in range(1, max_rounds + 1):
            if rnd == 1:
                cands = self.proposer.propose(finding)
            else:
                cands = self.proposer.refine(finding, candidate, conflicts)
            if not cands:
                break
            for cand in cands:
                evaluation = self.evaluator.evaluate(cand, checks)
                candidate = cand
                if evaluation.ok:
                    return LoopResult(finding.id, True, rnd, cand, evaluation)
                conflicts = evaluation.conflicts()
        return LoopResult(finding.id, False, max_rounds, candidate, evaluation)


@dataclass(frozen=True)
class HostApplyResult:
    host: str
    candidate: PatchCandidate
    diff: str
    applied: bool
    dry_run: bool


def apply_to_host(
    guard: ScopeGuard, candidate: PatchCandidate, host: str, *, approved: bool = False
) -> HostApplyResult:
    """Apply a validated candidate to a real host. Guarded by PATCH_APPLY.

    The guard requires ``enable_patch_apply`` **and** ``approved=True`` and that
    ``host`` is in scope. In dry-run the unified diff is returned and nothing is
    written; patches are **never** auto-applied to production.
    """
    decision = guard.authorize(ActionClass.PATCH_APPLY, target=host, approved=approved)
    diff = candidate.unified_diff()

    if decision.dry_run:
        guard.audit.append(
            "patch.apply.plan",
            {"host": host, "path": candidate.path, "finding": candidate.finding_id},
        )
        return HostApplyResult(host, candidate, diff, applied=False, dry_run=True)

    Path(candidate.path).write_text(candidate.hardened, encoding="utf-8")
    guard.audit.append(
        "patch.apply",
        {"host": host, "path": candidate.path, "finding": candidate.finding_id, "approved": approved},
    )
    return HostApplyResult(host, candidate, diff, applied=True, dry_run=False)
