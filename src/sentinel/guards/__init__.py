"""The single authorization path. Import ``ScopeGuard`` from here."""

from .scope_guard import Decision, ScopeGuard

__all__ = ["ScopeGuard", "Decision"]
