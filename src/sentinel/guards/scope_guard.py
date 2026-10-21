"""ScopeGuard — the one and only authorization gate.

Every active capability in SAKI-MORI must obtain a :class:`Decision` from
``ScopeGuard.authorize(...)`` before acting. The guard is constructed once via
:meth:`ScopeGuard.from_settings`, which:

1. loads and signature-verifies the ownership scope (fail closed),
2. verifies the operator consent against the current scope hash (fail closed),
3. checks the kill-switch,
4. opens the hash-chained audit log.

There is intentionally **no** keyword, env var, or config flag that disables the
guard. Removing the guard means editing source — which the OSS TERMS forbid and
which breaks the signed-build story.
"""

from __future__ import annotations

import threading
import time as _time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from ..core import killswitch
from ..core.actions import ACTIVE_CLASSES, SANDBOX_ONLY_CLASSES, ActionClass
from ..core.audit import AuditLog
from ..core.config import Settings, load_verified_scope, ScopeDoc
from ..core.consent import verify_consent
from ..core.errors import (
    ConsentRequired,
    GuardError,
    LimitExceeded,
    ModeViolation,
    ScopeViolation,
)


@dataclass(frozen=True)
class Decision:
    """Returned only when an action is authorized. Carries the execution mode."""

    action: ActionClass
    target: Optional[str]
    environment: Optional[str]
    dry_run: bool
    reason: str = "authorized"
    at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class ScopeGuard:
    def __init__(
        self,
        settings: Settings,
        scope: ScopeDoc,
        audit: AuditLog,
        *,
        consent_verified: bool,
    ) -> None:
        self.settings = settings
        self.scope = scope
        self.audit = audit
        self._consent_verified = consent_verified
        self._lock = threading.Lock()
        self._targets_this_run: set[str] = set()
        self._action_times: list[float] = []

    # ------------------------------------------------------------------ #
    # construction (the single supported entry point)
    # ------------------------------------------------------------------ #
    @classmethod
    def from_settings(cls, settings: Settings) -> "ScopeGuard":
        p = settings.paths
        killswitch.check(p.killswitch_file)  # refuse to even build if engaged
        scope = load_verified_scope(p.scope_file, p.scope_sig_file, p.scope_pubkey_file)
        # Fail closed unless consent verifies against the *current* scope hash.
        verify_consent(p.consent_file, p.consent_pubkey_file, scope.scope_hash())
        audit = AuditLog(p.audit_file)
        guard = cls(settings, scope, audit, consent_verified=True)
        audit.append(
            "guard.init",
            {
                "scope_hash": scope.scope_hash(),
                "dry_run": settings.dry_run,
                "toggles": settings.toggles.model_dump(),
            },
        )
        return guard

    # ------------------------------------------------------------------ #
    # the gate
    # ------------------------------------------------------------------ #
    def authorize(
        self,
        action: ActionClass,
        target: Optional[str] = None,
        *,
        environment: Optional[str] = None,
        approved: bool = False,
    ) -> Decision:
        """Authorize an action or raise a :class:`GuardError`. Always audited."""
        with self._lock:
            try:
                self._check(action, target, environment, approved)
            except GuardError as exc:
                self.audit.append(
                    "authorize.deny",
                    {
                        "action": action.value,
                        "target": target,
                        "environment": environment,
                        "error": type(exc).__name__,
                        "reason": str(exc),
                    },
                )
                raise
            decision = Decision(
                action=action,
                target=target,
                environment=environment,
                dry_run=self.settings.dry_run,
            )
            if action in ACTIVE_CLASSES and target:
                self._targets_this_run.add(target)
                self._action_times.append(_time.monotonic())
            self.audit.append(
                "authorize.allow",
                {
                    "action": action.value,
                    "target": target,
                    "environment": environment,
                    "dry_run": decision.dry_run,
                },
            )
            return decision

    # ------------------------------------------------------------------ #
    # checks (fail closed)
    # ------------------------------------------------------------------ #
    def _check(
        self,
        action: ActionClass,
        target: Optional[str],
        environment: Optional[str],
        approved: bool,
    ) -> None:
        # 0. kill-switch and consent are checked on every single call.
        killswitch.check(self.settings.paths.killswitch_file)
        if not self._consent_verified:
            raise ConsentRequired("guard has no verified consent")

        t = self.settings.toggles

        # 1. BLOCK is purely defensive (drop inbound traffic). Target need not be
        #    in scope, but blocking must be explicitly enabled.
        if action is ActionClass.BLOCK:
            if not t.enable_blocking:
                raise ModeViolation("blocking disabled (toggles.enable_blocking=false)")
            return

        # 2. PATCH_PROPOSE only generates text; allowed with consent/scope present.
        if action is ActionClass.PATCH_PROPOSE:
            return

        # 3. PASSIVE_READ: if a target is named it must be in scope; no toggle.
        if action is ActionClass.PASSIVE_READ:
            if target is not None and not self.scope.contains(target):
                raise ScopeViolation(f"target {target!r} is outside the signed scope")
            return

        # 4. Everything below is an ACTIVE class and needs a target in scope.
        if target is None:
            raise ScopeViolation(f"action {action.value} requires an in-scope target")
        if not self.scope.contains(target):
            raise ScopeViolation(f"target {target!r} is outside the signed scope")

        self._enforce_limits()

        if action is ActionClass.ACTIVE_SCAN:
            if not t.enable_active_scan:
                raise ModeViolation("active scan disabled (toggles.enable_active_scan=false)")
            return

        if action is ActionClass.REDTEAM_ATTACK:
            # Hard rules: sandbox only, never production — independent of toggles.
            if self.scope.is_production(target):
                raise ModeViolation(
                    f"redteam attack refused: {target!r} is flagged production"
                )
            if environment != "sandbox":
                raise ModeViolation(
                    "redteam attack refused: environment must be 'sandbox' (isolated replica)"
                )
            if not t.enable_sandbox_redteam:
                raise ModeViolation(
                    "redteam disabled (toggles.enable_sandbox_redteam=false)"
                )
            return

        if action is ActionClass.PATCH_APPLY:
            if not t.enable_patch_apply:
                raise ModeViolation("patch apply disabled (toggles.enable_patch_apply=false)")
            if not approved:
                raise ModeViolation("patch apply requires explicit human approval (approved=True)")
            return

        # Unknown action class -> fail closed.
        raise ModeViolation(f"unhandled action class {action!r}")

    def _enforce_limits(self) -> None:
        lim = self.settings.limits
        if len(self._targets_this_run) >= lim.max_targets_per_run:
            raise LimitExceeded(f"max_targets_per_run={lim.max_targets_per_run} reached")

        # sliding-window rate limit
        now = _time.monotonic()
        window_start = now - 60.0
        self._action_times = [ts for ts in self._action_times if ts >= window_start]
        if len(self._action_times) >= lim.rate_per_minute:
            raise LimitExceeded(f"rate_per_minute={lim.rate_per_minute} exceeded")

        bounds = lim.window_bounds()
        if bounds is not None:
            start, end = bounds
            now_t = datetime.now().time()
            in_window = (start <= now_t <= end) if start <= end else (now_t >= start or now_t <= end)
            if not in_window:
                raise LimitExceeded(f"outside allowed time window {lim.time_window}")
