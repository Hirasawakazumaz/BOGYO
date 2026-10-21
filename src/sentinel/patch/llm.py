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
from dataclasses import dataclass
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
@dataclass(frozen=True)
class Rule:
    """One hardening rule, in priority order within its service.

    ``pattern`` matches an existing (possibly commented-out) setting and is
    replaced by ``repl``. If ``ensure`` is set and ``present`` (default:
    ``pattern``) matches nowhere, the ``ensure`` line is inserted instead, at a
    service-specific spot (see :func:`_insert`). Rules only ever tighten.
    """

    pattern: str
    repl: str
    why: str
    ensure: str = ""
    present: str = ""


def _sshd(key: str, value: str, why: str) -> Rule:
    # active ``Key value`` / ``Key=value`` lines, or a commented default ``#Key value``
    # (single token, so explanatory comment prose is left alone); keeps indentation.
    pat = rf"(?im)^([ \t]*)(?:{key}(?:[ \t]*=[ \t]*|[ \t]+).*|#[ \t]*{key}[ \t]+\S+[ \t]*)$"
    return Rule(pat, rf"\g<1>{key} {value}", why, ensure=f"{key} {value}")


def _kv(key: str, value: str, why: str) -> Rule:
    # ``key = value`` files (postgresql.conf, sysctl.conf), commented or not.
    k = re.escape(key)
    return Rule(rf"(?im)^([ \t]*)#?[ \t]*{k}[ \t]*=.*$", rf"\g<1>{key} = {value}", why,
                ensure=f"{key} = {value}")


#: service -> rules, highest priority first (``refine`` keeps only the first).
_RULES: dict[str, list[Rule]] = {
    "sshd": [
        _sshd("PermitRootLogin", "no", "disable direct root SSH login"),
        _sshd("PasswordAuthentication", "no", "require keys, not passwords"),
        _sshd("PermitEmptyPasswords", "no", "refuse empty passwords"),
        _sshd("KbdInteractiveAuthentication", "no", "disable keyboard-interactive (password) auth"),
        _sshd("ChallengeResponseAuthentication", "no", "disable challenge-response (password) auth"),
        _sshd("HostbasedAuthentication", "no", "disable host-based trust"),
        _sshd("IgnoreRhosts", "yes", "ignore legacy .rhosts files"),
        _sshd("PermitUserEnvironment", "no", "stop users injecting environment into sshd"),
        _sshd("X11Forwarding", "no", "disable X11 forwarding"),
        _sshd("MaxAuthTries", "3", "limit authentication attempts per connection"),
        _sshd("LoginGraceTime", "30", "shorten the unauthenticated login window"),
    ],
    "nginx": [
        Rule(r"(?im)^([ \t]*)server_tokens[ \t]+on[ \t]*;", r"\g<1>server_tokens off;",
             "hide nginx version banner", ensure="server_tokens off;",
             present=r"(?im)^[ \t]*server_tokens\b"),
        # only rewrites lists that still allow SSLv2/3, TLSv1 or TLSv1.1 (never weakens)
        Rule(r"(?im)^([ \t]*)ssl_protocols\b[^;]*\b(?:SSLv[23]|TLSv1(?:\.1)?)(?![.\d])[^;]*;",
             r"\g<1>ssl_protocols TLSv1.2 TLSv1.3;", "drop SSLv3/TLSv1.0/TLSv1.1"),
        Rule(r"(?im)^([ \t]*)autoindex[ \t]+on[ \t]*;", r"\g<1>autoindex off;",
             "disable directory listings"),
    ],
    "postgres": [
        _kv("ssl", "on", "require TLS for database connections"),
        Rule(r"(?im)^([ \t]*)#?[ \t]*password_encryption[ \t]*=[ \t]*'?(?:md5|on|off)\b'?.*$",
             r"\g<1>password_encryption = scram-sha-256",
             "hash new passwords with SCRAM, not MD5"),
        _kv("log_connections", "on", "log connections for audit"),
        _kv("log_disconnections", "on", "log disconnections for audit"),
    ],
    "sysctl": [
        _kv("net.ipv4.tcp_syncookies", "1", "SYN-flood protection"),
        _kv("net.ipv4.conf.all.accept_redirects", "0", "ignore ICMP redirects (IPv4)"),
        _kv("net.ipv6.conf.all.accept_redirects", "0", "ignore ICMP redirects (IPv6)"),
        _kv("net.ipv4.conf.all.send_redirects", "0", "do not send ICMP redirects"),
        _kv("net.ipv4.conf.all.accept_source_route", "0", "refuse source-routed packets"),
        _kv("net.ipv4.conf.all.rp_filter", "1", "reverse-path filtering against spoofing"),
        _kv("net.ipv4.icmp_echo_ignore_broadcasts", "1", "ignore broadcast pings (smurf)"),
        _kv("kernel.randomize_va_space", "2", "full ASLR"),
        _kv("fs.protected_hardlinks", "1", "hardlink protection"),
        _kv("fs.protected_symlinks", "1", "symlink protection"),
    ],
}

#: common alternative service names -> rule set
_ALIASES = {"ssh": "sshd", "openssh": "sshd", "postgresql": "postgres", "pg": "postgres"}


def rules_for(service: str) -> list[Rule]:
    s = service.lower()
    return _RULES.get(_ALIASES.get(s, s), [])


def _insert(service: str, text: str, line: str) -> Optional[str]:
    """Insert a missing directive where the service will honour it (None: no safe spot)."""
    s = _ALIASES.get(service.lower(), service.lower())
    if s == "nginx":
        # inside the http {} context; a bare server/site snippet has no safe spot
        m = re.search(r"(?m)^([ \t]*)http[ \t]*\{[^\n]*\n", text)
        if m is None:
            return None
        return text[: m.end()] + f"{m.group(1)}    {line}\n" + text[m.end():]
    if s == "sshd":
        # directives after the first ``Match`` would only apply inside that block
        m = re.search(r"(?im)^[ \t]*Match[ \t]", text)
        if m is not None:
            return text[: m.start()] + f"{line}\n" + text[m.start():]
    if text and not text.endswith("\n"):
        text += "\n"
    return text + f"{line}\n"


class RuleBackend:
    """Deterministic hardening. ``refine`` returns the single most important change."""

    def _apply(self, service: str, text: str, rules: list[Rule]) -> tuple[str, list[str]]:
        hardened = text
        applied: list[str] = []
        for rule in rules:
            new = re.sub(rule.pattern, rule.repl, hardened)
            if new == hardened and rule.ensure and not re.search(rule.present or rule.pattern, hardened):
                new = _insert(service, hardened, rule.ensure) or hardened
            if new != hardened:
                hardened = new
                applied.append(rule.why)
        return hardened, applied

    def _candidate(self, finding: Finding, rules: list[Rule]) -> Optional[PatchCandidate]:
        hardened, applied = self._apply(finding.service, finding.original, rules)
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
        cand = self._candidate(finding, rules_for(finding.service))
        return [cand] if cand else []

    def refine(
        self, finding: Finding, candidate: PatchCandidate, conflicts: list[str]
    ) -> list[PatchCandidate]:
        # Be more conservative: apply only the single highest-priority rule.
        cand = self._candidate(finding, rules_for(finding.service)[:1])
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


class LocalAIBackend:
    """Local AI (OpenAI-compatible / Ollama) proposer. Offline-safe fallback to rules.

    Keeps everything on the operator's own machine — no cloud. Uses the chat
    completions schema served by Ollama's /v1, LM Studio, llama.cpp, vLLM, etc.
    """

    SYSTEM = AnthropicBackend.SYSTEM

    def __init__(self, endpoint: str, model: str) -> None:
        self.endpoint = endpoint
        self.model = model
        self._fallback = RuleBackend()

    def _ask(self, finding: Finding, extra: str = "") -> list[PatchCandidate]:
        import requests  # optional dependency

        prompt = (
            f"Service: {finding.service}\nFinding: {finding.title}\n{finding.detail}\n{extra}\n"
            f"--- current {finding.path} ---\n{finding.original}\nReturn the hardened file content only."
        )
        resp = requests.post(
            self.endpoint,
            json={"model": self.model, "messages": [
                {"role": "system", "content": self.SYSTEM},
                {"role": "user", "content": prompt}], "stream": False},
            timeout=120,
        )
        resp.raise_for_status()
        data = resp.json()
        hardened = data["choices"][0]["message"]["content"].strip() + "\n"
        if not hardened.strip() or hardened == finding.original:
            return []
        return [PatchCandidate(
            finding_id=finding.id, service=finding.service, path=finding.path,
            rationale=f"local-AI hardening ({self.model})", original=finding.original,
            hardened=hardened, changes=["local-ai hardening"])]

    def propose(self, finding: Finding) -> list[PatchCandidate]:
        try:
            return self._ask(finding) or self._fallback.propose(finding)
        except Exception:  # noqa: BLE001
            return self._fallback.propose(finding)

    def refine(self, finding: Finding, candidate: PatchCandidate, conflicts: list[str]) -> list[PatchCandidate]:
        extra = f"Previous candidate conflicted: {', '.join(conflicts)}. Be more conservative."
        try:
            return self._ask(finding, extra) or self._fallback.refine(finding, candidate, conflicts)
        except Exception:  # noqa: BLE001
            return self._fallback.refine(finding, candidate, conflicts)


class ClaudeCliBackend:
    """Use the logged-in Claude Code CLI (`claude -p`) — the subscription, no API key.

    Simplifies setup: the operator just runs `claude` once to log in; this backend
    shells out to it. Offline-safe: any failure falls back to the rule backend.
    """

    SYSTEM = AnthropicBackend.SYSTEM

    def __init__(self, cli: str = "claude") -> None:
        self.cli = cli
        self._fallback = RuleBackend()

    def _ask(self, finding: Finding, extra: str = "") -> list[PatchCandidate]:
        import shutil
        import subprocess

        if shutil.which(self.cli) is None:
            raise RuntimeError(f"{self.cli} CLI not found")
        prompt = (
            f"{self.SYSTEM}\n\nService: {finding.service}\nFinding: {finding.title}\n{finding.detail}\n{extra}\n"
            f"--- current {finding.path} ---\n{finding.original}\nReturn ONLY the hardened file content."
        )
        proc = subprocess.run([self.cli, "-p", prompt], capture_output=True, text=True, timeout=180, check=False)
        hardened = (proc.stdout or "").strip() + "\n"
        if proc.returncode != 0 or not hardened.strip() or hardened == finding.original:
            return []
        return [PatchCandidate(
            finding_id=finding.id, service=finding.service, path=finding.path,
            rationale="Claude Code CLI hardening", original=finding.original,
            hardened=hardened, changes=["claude-cli hardening"])]

    def propose(self, finding: Finding) -> list[PatchCandidate]:
        try:
            return self._ask(finding) or self._fallback.propose(finding)
        except Exception:  # noqa: BLE001
            return self._fallback.propose(finding)

    def refine(self, finding: Finding, candidate: PatchCandidate, conflicts: list[str]) -> list[PatchCandidate]:
        extra = f"Previous candidate conflicted: {', '.join(conflicts)}. Be more conservative."
        try:
            return self._ask(finding, extra) or self._fallback.refine(finding, candidate, conflicts)
        except Exception:  # noqa: BLE001
            return self._fallback.refine(finding, candidate, conflicts)


def default_backend(governor=None, settings=None) -> PatchBackend:
    """Choose a backend from settings/provider, else env key, else offline rules.

    provider "local" → local AI; "cli" → Claude Code CLI (subscription login);
    otherwise the Anthropic API backend when a key is present (metered by the
    governor); otherwise the deterministic offline rules.
    """
    usage = getattr(settings, "usage", None)
    provider = getattr(usage, "provider", "api")
    if provider == "local" and usage is not None:
        return LocalAIBackend(usage.local_endpoint, usage.local_model)
    if provider == "cli":
        return ClaudeCliBackend()
    if os.environ.get("ANTHROPIC_API_KEY"):
        return AnthropicBackend(governor=governor)
    return RuleBackend()
