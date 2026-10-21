"""Drive the Textual dashboard headlessly (skipped without the [tui] extra)."""

from __future__ import annotations

import asyncio

import pytest

pytest.importorskip("textual")


def test_dashboard_screens_and_timers_run(make_env, tmp_path):
    from sentinel.dashboard.app import SentinelDashboardApp

    sp = str(tmp_path / "settings.yaml")
    make_env().settings.save(sp)

    async def drive():
        app = SentinelDashboardApp(sp, refresh_interval=0.3)
        async with app.run_test(size=(160, 50)) as pilot:
            await pilot.pause(0.8)  # let the refresh + pipeline timers fire
            for key in ("c", "escape", "h", "escape", "m", "escape", "r"):
                await pilot.press(key)
                await pilot.pause(0.2)
            await pilot.pause(0.5)
            return app.title

    assert asyncio.run(drive())
