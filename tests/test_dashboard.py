"""World map rendering, geo safety, and dashboard aggregation (offline)."""

from __future__ import annotations

from sentinel.core.actions import ActionClass
from sentinel.core.config import GeoConfig
from sentinel.dashboard import DashboardModel, render_snapshot
from sentinel.dashboard.worldmap import H, W, Marker, render_grid
from sentinel.guards import ScopeGuard
from sentinel.intel.geo import country_centroid, lookup_ip


def test_worldmap_dimensions_and_markers():
    home = country_centroid("JP")
    attackers = [Marker(lat=61.5, lon=105.3, blocked=True), Marker(lat=39.8, lon=-98.6, blocked=False)]
    grid = render_grid(home, attackers)
    assert len(grid) == H and all(len(r) == W for r in grid)
    joined = "\n".join(grid)
    assert "@" in joined  # home
    assert "x" in joined  # blocked attacker
    assert "!" in joined  # active attacker
    # an arrow glyph is drawn somewhere
    assert any(ch in joined for ch in ("-", "|", "/", "\\"))


def test_geo_private_ip_not_sent_and_disabled_by_default():
    cfg = GeoConfig()  # enable_geo_lookup defaults False
    assert lookup_ip("10.0.0.5", cfg).ok is False      # private -> never resolved
    assert lookup_ip("8.8.8.8", cfg).ok is False       # lookup disabled -> unknown


def test_country_centroid_known_unknown():
    assert country_centroid("JP") is not None
    assert country_centroid("ZZ") is None


def test_dashboard_aggregates_audit(make_env):
    env = make_env(enable_blocking=True)
    guard = ScopeGuard.from_settings(env.settings)
    # produce some audited activity
    guard.authorize(ActionClass.BLOCK, target="198.51.100.9")
    guard.audit.append("block.plan", {"ip": "198.51.100.9", "ttl": 3600})
    guard.audit.append("authorize.deny", {"action": "active_scan", "target": "8.8.8.8"})

    state = DashboardModel(env.settings).build()
    assert any(r["ip"] == "198.51.100.9" for r in state.blocked_ips)
    assert state.denies >= 1 and state.allows >= 1
    assert state.audit_intact is True
    snap = render_snapshot(state)
    assert "GLOBAL DEFENSE GRID" in snap
    assert "USAGE GOVERNOR" in snap
    assert "WORLD MAP" in snap
