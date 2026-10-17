"""Patch generation + sandbox conflict-evaluation loop (guarded)."""

from .evaluator import (
    CheckResult,
    ConflictEvaluator,
    EvalResult,
    HostApplyResult,
    LoopResult,
    PatchLoop,
    apply_to_host,
)
from .llm import AnthropicBackend, PatchBackend, RuleBackend, default_backend
from .model import Finding, PatchCandidate
from .proposer import PatchProposer

__all__ = [
    "Finding",
    "PatchCandidate",
    "PatchProposer",
    "ConflictEvaluator",
    "EvalResult",
    "CheckResult",
    "PatchLoop",
    "LoopResult",
    "HostApplyResult",
    "apply_to_host",
    "PatchBackend",
    "RuleBackend",
    "AnthropicBackend",
    "default_backend",
]
