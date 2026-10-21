"""BOGYO: authorized, consent-gated proactive defense for Linux servers.

Design rule (non-negotiable): every active capability is routed through a single
guard (``sentinel.guards.scope_guard``). If consent, a signed scope, or the
non-production/sandbox conditions are not satisfied, the guard fails closed and
the operation is refused. There is no hidden flag or environment variable that
disables the guard.
"""

__version__ = "0.1.0"
