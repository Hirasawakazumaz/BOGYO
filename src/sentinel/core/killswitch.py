"""Emergency stop. If the kill-switch file exists, nothing is allowed to run."""

from __future__ import annotations

from pathlib import Path

from .errors import KillSwitchEngaged


def check(path: str | Path) -> None:
    """Raise :class:`KillSwitchEngaged` if the kill-switch file is present."""
    if Path(path).exists():
        raise KillSwitchEngaged(
            f"kill-switch engaged ({path}); remove the file to resume operation"
        )


def engage(path: str | Path, reason: str = "") -> None:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(f"ENGAGED {reason}\n", encoding="utf-8")


def release(path: str | Path) -> None:
    Path(path).unlink(missing_ok=True)
