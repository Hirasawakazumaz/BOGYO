"""Data types shared across the patch module (no heavy deps, import-safe)."""

from __future__ import annotations

import difflib
from dataclasses import dataclass, field
from typing import Optional


@dataclass(frozen=True)
class Finding:
    """A normalized security finding to be hardened against.

    ``original`` is the current content of ``path`` (the config to harden); the
    backend transforms it into a hardened variant.
    """

    id: str
    target: str
    service: str
    title: str
    detail: str = ""
    path: str = ""
    original: str = ""


@dataclass(frozen=True)
class PatchCandidate:
    """A proposed hardening change. Carries both sides so a unified diff is exact."""

    finding_id: str
    service: str
    path: str
    rationale: str
    original: str
    hardened: str
    changes: list[str] = field(default_factory=list)

    def is_noop(self) -> bool:
        return self.original == self.hardened

    def unified_diff(self) -> str:
        diff = difflib.unified_diff(
            self.original.splitlines(keepends=True),
            self.hardened.splitlines(keepends=True),
            fromfile=f"a/{self.path}",
            tofile=f"b/{self.path}",
            lineterm="\n",
        )
        return "".join(diff)
