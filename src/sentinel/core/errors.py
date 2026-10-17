"""Exception hierarchy. Every guard failure is fail-closed: it raises, never returns.

Nothing in this package should catch :class:`GuardError` broadly and continue with
an active operation. Catch narrowly, log, and abort.
"""

from __future__ import annotations


class SentinelError(Exception):
    """Base class for all Sentinel-Guard errors."""


class ConfigError(SentinelError):
    """Malformed, missing, or internally inconsistent configuration."""


class SigningError(SentinelError):
    """Key loading, signing, or signature verification failure."""


class GuardError(SentinelError):
    """Base class for every authorization refusal (fail-closed)."""


class KillSwitchEngaged(GuardError):
    """The kill-switch file is present; all operations must stop immediately."""


class ConsentRequired(GuardError):
    """Signed operator consent is missing, invalid, or no longer matches the scope."""


class ScopeViolation(GuardError):
    """A target is outside the signed ownership scope, or the scope is unverified."""


class ModeViolation(GuardError):
    """An action is not permitted in the current mode (e.g. active attack on prod,
    or an active action while a required toggle is off)."""


class LimitExceeded(GuardError):
    """A configured safety limit (targets, concurrency, rate, time window) was hit."""
