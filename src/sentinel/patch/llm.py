"""Patch-generation backends behind one clean interface.

``PatchBackend`` has two methods: ``propose`` (first pass) and ``refine`` (given a
candidate that conflicted in the sandbox, try again more conservatively).

* :class:`RuleBackend` — **deterministic, fully offline** config-hardening rules.
  This is the default so the core stays testable without network or API keys.
* :class:`AnthropicBackend` — lazily imports ``anthropic`` (the optional ``agent``
  extra) and asks Claude for candidates, falling back to the rule backend on any
  error. Importing this module never imports ``anthropic``.

No backend ships exploit code; they only emit hardened configuration text.
"""

from __future__ import annotations

import os
import re
from typing import Optional, Protocol

from .model import Finding, PatchCandidate


class PatchBackend(Protocol):
    def propose(self, finding: Finding) -> list[PatchCandidate]: ...

    def refine(
        self, finding: Finding, candidate: PatchCandidate, conflicts: list[str]
    ) -> list[PatchCandidate]: ...


# --------------------------------------------------------------------------- #
# deterministic, offline rule backend
# --------------------------------------------------------------------------- #
#: service -> list of (regex, replacement, human rationale). Applied per line.
_RULES: dict[str, list[tuple[str, str, str]]] = {
    "sshd": [
        (r"(?im)^\s*#?\s*PermitRootLogin\s+.*$", "PermitRootLogin no", "disable direct root SSH login"),
        (r"(?im)^\s*#?\s*PasswordAuthentication\s+.*$", "PasswordAuthentication no", "require keys, not passwords"),
        (r"(?im)^\s*#?\s*X11Forwarding\s+.*$", "X11Forwarding no", "disable X11 forwarding"),
    ],
    "nginx": [
        (r"(?im)^(\s*)server_tokens\s+on\s*;", r"\1server_tokens off;", "hide nginx version banner"),
    ],
    "postgres": [
        (r"(?im)^\s*#?\s*ssl\s*=\s*.*$", "ssl = on", "require TLS for database connections"),
    ],
}


class RuleBackend:
    """Deterministic hardening. ``refine`` returns the single most important change."""

    def _apply(self, text: str, rules: list[tuple[str, str, str]]) -> tuple[str, list[str]]:
        hardened = text
        applied: list[str] = []
        for pattern, repl, why in rules:
            new = re.sub(pattern, repl, hardened)
            if new != hardened:
                hardened = new
                applied.append(why)
        return hardened, applied

    def _candidate(self, finding: Finding, rules: list[tuple[str, str, str]]) -> Optional[PatchCandidate]:
        hardened, applied = self._apply(finding.original, rules)
        if hardened == finding.original:
            return None
        return PatchCandidate(
            finding_id=finding.id,
            service=finding.service,
            path=finding.path,
            rationale="; ".join(applied),
            original=finding.original,
            hardened=hardened,
            changes=applied,
        )

    def propose(self, finding: Finding) -> list[PatchCandidate]:
        rules = _RULES.get(finding.service.lower(), [])
        cand = self._candidate(finding, rules)
        return [cand] if cand else []

    def refine(
        self, finding: Finding, candidate: PatchCandidate, conflicts: list[str]
    ) -> list[PatchCandidate]:
        # Be more conservative: apply only the single highest-priority rule.
        rules = _RULES.get(finding.service.lower(), [])
        cand = self._candidate(finding, rules[:1])
        if cand is None or cand.hardened == candidate.hardened:
            return []
        return [cand]


# --------------------------------------------------------------------------- #
# LLM backend (optional; lazy import; safe fallback)
# --------------------------------------------------------------------------- #
class AnthropicBackend:
    """Claude-backed proposer. Lazily imports ``anthropic``; falls back to rules."""

    SYSTEM = (
        "You harden Linux service configuration for a defensive security tool. "
        "Return ONLY the full hardened config file content. Do not include exploits, "
        "attack payloads, or anything that weakens security."
    )

    def __init__(
        self,
        model: str = "claude-opus-4-8",
        api_key_env: str = "ANTHROPIC_API_KEY",
        governor=None,
    ) -> None:
        self.model = model
        self.api_key_env = api_key_env
        #: Optional sentinel.usage.Governor — picks the model from the remaining
        #: budget, gates calls when stopped, and records real token spend.
        self.governor = governor
        self._fallback = RuleBackend()

    def _client(self):
        import anthropic  # optional dependency (extras: agent)

        key = os.environ.get(self.api_key_env)
        if not key:
            raise RuntimeError(f"{self.api_key_env} not set")
        return anthropic.Anthropic(api_key=key)

    def _effective_model(self) -> str:
        """Let the usage governor choose the tier when it is metering (provider api)."""
        if self.governor is not None and getattr(self.governor.config, "provider", "api") == "api":
            return self.governor.state().model
        return self.model

    def _budget_allows(self) -> bool:
        if self.governor is None:
            return True
        return self.governor.state().allow_run

    def _ask(self, finding: Finding, op: str, extra: str = "") -> list[PatchCandidate]:
        client = self._client()
        model = self._effective_model()
        prompt = (
            f"Service: {finding.service}\nFinding: {finding.title}\n{finding.detail}\n"
            f"{extra}\n--- current {finding.path} ---\n{finding.original}\n"
            "Return the hardened file content only."
        )
        msg = client.messages.create(
            model=model,
            max_tokens=2048,
            system=self.SYSTEM,
            messages=[{"role": "user", "content": prompt}],
        )
        # Record REAL token spend from the API response usage block.
        self._record_usage(msg, model, op)
        hardened = "".join(getattr(b, "text", "") for b in msg.content).strip() + "\n"
        if not hardened.strip() or hardened == finding.original:
            return []
        return [
            PatchCandidate(
                finding_id=finding.id,
                service=finding.service,
                path=finding.path,
                rationale=f"LLM hardening ({model})",
                original=finding.original,
                hardened=hardened,
                changes=["llm-generated hardening"],
            )
        ]

    def _record_usage(self, msg, model: str, op: str) -> None:
        if self.governor is None:
            return
        usage = getattr(msg, "usage", None)
        in_t = int(getattr(usage, "input_tokens", 0) or 0)
        out_t = int(getattr(usage, "output_tokens", 0) or 0)
        self.governor.record(in_t + out_t, model=model, op=op)

    def propose(self, finding: Finding) -> list[PatchCandidate]:
        if not self._budget_allows():
            # daily token budget reached — stay offline until the governor resets
            return self._fallback.propose(finding)
        try:
            cands = self._ask(finding, op="patch.propose")
            return cands or self._fallback.propose(finding)
        except Exception:  # noqa: BLE001 - never let the LLM break the loop
            return self._fallback.propose(finding)

    def refine(
        self, finding: Finding, candidate: PatchCandidate, conflicts: list[str]
    ) -> list[PatchCandidate]:
        if not self._budget_allows():
            return self._fallback.refine(finding, candidate, conflicts)
        extra = f"The previous candidate caused these conflicts: {', '.join(conflicts)}. Be more conservative."
        try:
            cands = self._ask(finding, op="patch.refine", extra=extra)
            return cands or self._fallback.refine(finding, candidate, conflicts)
        except Exception:  # noqa: BLE001
            return self._fallback.refine(finding, candidate, conflicts)


def default_backend(governor=None) -> PatchBackend:
    """Pick the LLM backend if a key is present, else the deterministic rules.

    Pass a ``sentinel.usage.Governor`` to meter real token spend and let the daily
    budget drive model selection and stop/resume.
    """
    if os.environ.get("ANTHROPIC_API_KEY"):
        return AnthropicBackend(governor=governor)
    return RuleBackend()
