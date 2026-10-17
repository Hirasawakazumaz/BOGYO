"""LangGraph-style orchestration: intake -> scan -> sandbox -> patch -> eval -> report.

Every node calls the guard first. The import of ``langgraph`` is **lazy**: the
pure-Python :class:`SentinelPipeline` runs the exact same guarded node functions
in order with no third-party dependency, so ``import sentinel.graph`` and the
core test suite work offline without the ``agent`` extra. :func:`build_langgraph`
wires the identical nodes into a real ``langgraph.StateGraph`` when it is
installed.

Resilience vs. fail-closed: a node whose capability the guard refuses performs
**no** action — the refusal is recorded (and audited by the guard) and the node
is marked ``skipped`` so the pipeline can still, e.g., produce a report. No node
ever continues past a refusal with the denied operation.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Optional

from ..core.errors import GuardError
from ..guards import ScopeGuard
from ..intake import detect_bruteforce_ips
from ..patch import ConflictEvaluator, Finding, PatchProposer
from ..patch.llm import PatchBackend
from ..report import ReportBuilder
from ..sandbox import SandboxReplay
from ..scan import Scanner


@dataclass
class PipelineConfig:
    target: Optional[str] = None
    tool: str = "nmap"
    log_lines: list[str] = field(default_factory=list)
    bruteforce_threshold: int = 5
    replica: Optional[str] = None
    validations: list[tuple[str, list[str]]] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    checks: Optional[list[tuple[str, list[str]]]] = None
    patch_backend: Optional[PatchBackend] = None
    report_md: Optional[str] = None
    report_json: Optional[str] = None


@dataclass
class PipelineState:
    config: PipelineConfig
    attacker_ips: list[str] = field(default_factory=list)
    scan_plans: list[Any] = field(default_factory=list)
    sandbox_plan: Any = None
    candidates: list[Any] = field(default_factory=list)
    evaluations: list[Any] = field(default_factory=list)
    report: Any = None
    skipped: list[str] = field(default_factory=list)


class SentinelPipeline:
    """Runs the guarded nodes in order. Pure Python; no langgraph required."""

    def __init__(self, guard: ScopeGuard) -> None:
        self.guard = guard

    # -- nodes (each calls the guard via its guarded component) -------------- #
    def node_intake(self, state: PipelineState) -> PipelineState:
        signals = detect_bruteforce_ips(
            state.config.log_lines, threshold=state.config.bruteforce_threshold
        )
        state.attacker_ips = [s.ip for s in signals]
        self.guard.audit.append("graph.intake", {"attacker_ips": state.attacker_ips})
        return state

    def node_scan(self, state: PipelineState) -> PipelineState:
        if not state.config.target:
            return self._skip(state, "scan", "no target configured")
        try:
            plan = Scanner(self.guard).scan(state.config.target, tool=state.config.tool)
            state.scan_plans.append(plan)
        except GuardError as exc:
            self._mark_skip(state, "scan", exc)
        return state

    def node_sandbox(self, state: PipelineState) -> PipelineState:
        if not state.config.replica:
            return self._skip(state, "sandbox", "no replica configured")
        sb = SandboxReplay(self.guard, state.config.replica)
        try:
            state.sandbox_plan = sb.replay(state.config.validations)
        except GuardError as exc:
            self._mark_skip(state, "sandbox", exc)
        return state

    def node_patch_propose(self, state: PipelineState) -> PipelineState:
        proposer = PatchProposer(self.guard, state.config.patch_backend)
        for finding in state.config.findings:
            try:
                state.candidates.extend(proposer.propose(finding))
            except GuardError as exc:
                self._mark_skip(state, "patch_propose", exc)
                break
        return state

    def node_conflict_eval(self, state: PipelineState) -> PipelineState:
        evaluator = ConflictEvaluator(self.guard)
        for cand in state.candidates:
            try:
                state.evaluations.append(evaluator.evaluate(cand, state.config.checks))
            except GuardError as exc:
                self._mark_skip(state, "conflict_eval", exc)
                break
        return state

    def node_report(self, state: PipelineState) -> PipelineState:
        builder = ReportBuilder(self.guard.settings.paths.audit_file)
        state.report = builder.write(state.config.report_md, state.config.report_json)
        self.guard.audit.append("graph.report", {"breaches": state.report.breaches})
        return state

    # -- helpers ------------------------------------------------------------- #
    def _skip(self, state: PipelineState, node: str, reason: str) -> PipelineState:
        state.skipped.append(f"{node}:{reason}")
        self.guard.audit.append("graph.skip", {"node": node, "reason": reason})
        return state

    def _mark_skip(self, state: PipelineState, node: str, exc: GuardError) -> None:
        state.skipped.append(f"{node}:{type(exc).__name__}")
        self.guard.audit.append(
            "graph.skip", {"node": node, "reason": str(exc), "error": type(exc).__name__}
        )

    @property
    def nodes(self) -> list[tuple[str, Callable[[PipelineState], PipelineState]]]:
        return [
            ("intake", self.node_intake),
            ("scan", self.node_scan),
            ("sandbox", self.node_sandbox),
            ("patch_propose", self.node_patch_propose),
            ("conflict_eval", self.node_conflict_eval),
            ("report", self.node_report),
        ]

    def run(self, config: PipelineConfig) -> PipelineState:
        state = PipelineState(config=config)
        self.guard.audit.append("graph.start", {"target": config.target, "replica": config.replica})
        for _, fn in self.nodes:
            state = fn(state)
        self.guard.audit.append("graph.done", {"skipped": state.skipped})
        return state


def build_langgraph(guard: ScopeGuard):
    """Wire the same guarded nodes into a real ``langgraph.StateGraph`` (lazy import).

    Raises a clear error if the optional ``agent`` extra is not installed. The
    compiled graph's state is ``{"state": PipelineState}``; invoke it with
    ``graph.invoke({"state": PipelineState(config=...)})``.
    """
    try:
        from langgraph.graph import END, START, StateGraph
    except ImportError as exc:  # pragma: no cover - requires the agent extra
        raise RuntimeError(
            "langgraph is not installed; install the optional extra: pip install '.[agent]'"
        ) from exc

    from typing import TypedDict

    class _GS(TypedDict):
        state: PipelineState

    pipe = SentinelPipeline(guard)
    g = StateGraph(_GS)

    def _wrap(fn):
        return lambda d: {"state": fn(d["state"])}

    names = [name for name, _ in pipe.nodes]
    for name, fn in pipe.nodes:
        g.add_node(name, _wrap(fn))
    g.add_edge(START, names[0])
    for a, b in zip(names, names[1:]):
        g.add_edge(a, b)
    g.add_edge(names[-1], END)
    return g.compile()
