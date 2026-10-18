"""Cyber / CASIO-world-map defense dashboard.

``DashboardModel`` aggregates state; ``render_snapshot`` draws a plain-text frame
(no extra deps); ``run_app`` launches the interactive Textual UI (``[tui]`` extra,
imported lazily so the rest of the package stays dependency-light and offline).
"""

from .model import DashboardModel, DashboardState
from .snapshot import render_snapshot

__all__ = ["DashboardModel", "DashboardState", "render_snapshot", "run_app"]


def run_app(settings_path: str) -> None:
    """Launch the interactive Textual dashboard (lazy import of the [tui] extra)."""
    try:
        from .app import SentinelDashboardApp
    except ImportError as exc:  # pragma: no cover - needs the tui extra
        raise RuntimeError(
            "the interactive dashboard needs the TUI extra: pip install '.[tui]'"
        ) from exc
    SentinelDashboardApp(settings_path=settings_path).run()
