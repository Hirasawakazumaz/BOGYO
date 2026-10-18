"""Plain-text dashboard snapshot (no Textual needed) — used by `sentinel dashboard --once`.

Renders the CASIO-world-map / cyber panel as a single string so it works over any
terminal or in CI, and is easy to unit-test. The interactive Textual app reuses
the same :class:`DashboardState` and world map.
"""

from __future__ import annotations

from datetime import datetime

from .model import DashboardState
from .worldmap import W, render_grid

_TL, _TR, _BL, _BR, _H, _V = "╔", "╗", "╚", "╝", "═", "║"


def _box(title: str, lines: list[str], width: int) -> list[str]:
    inner = width - 2
    top = f"{_TL}{_H} {title} ".ljust(width - 1, _H) + _TR
    out = [top]
    for ln in lines:
        out.append(f"{_V} " + ln[: inner - 2].ljust(inner - 2) + f" {_V}")
    out.append(f"{_BL}{_H * inner}{_BR}")
    return out


def render_snapshot(state: DashboardState) -> str:
    width = W + 4
    clock = datetime.now().astimezone().strftime("%Y-%m-%d %H:%M:%S %Z")
    lines: list[str] = []
    lines.append("")
    title = "SENTINEL-GUARD // GLOBAL DEFENSE GRID"
    lines.append(title.center(width))
    lines.append(f"{clock}".center(width))
    lines.append("")

    # world map
    grid = render_grid(state.home_latlon, state.attackers)
    home_tag = f"{state.home_label}({state.home_country})"
    lines += _box(f"WORLD MAP  @={home_tag}  x=blocked  !=active", grid, width)

    # stats
    u = state.usage
    tests = state.tests or {}
    test_str = (
        f"{tests.get('passed','?')}/{tests.get('total','?')} pass"
        if state.tests else "n/a"
    )
    stat_lines = [
        f"blocked IPs : {len(state.blocked_ips):<4}   breaches: {state.breaches:<4}   vulns: {state.vuln_count:<4}",
        f"authorizations: allow {state.allows:<5} deny {state.denies:<5}   tests: {test_str}",
        f"patches: proposed {state.proposed_patches:<4} applied {len(state.applied_patches):<4}   audit: {'INTACT' if state.audit_intact else 'TAMPERED'}",
    ]
    lines += _box("DEFENSE STATUS", stat_lines, width)

    # usage governor
    if u is not None:
        usage_lines = [
            f"provider: {u.provider:<4}  level: {u.level:<10}  model: {u.model}",
            f"tokens today: {u.tokens_today:,} / {u.budget:,}  {u.bar(28)} {int(u.fraction*100)}%",
            f"runs/hour: {u.runs_per_hour:<4}  run allowed: {'YES' if u.allow_run else 'NO (stopped)'}  resets: {u.resets_at[:16]}",
        ]
        lines += _box("CLAUDE USAGE GOVERNOR", usage_lines, width)

    # lists
    ip_lines = [f"{r['ip']:<40} {r.get('country','??'):<4} {'BLOCKED' if r['blocked'] else 'seen'}"
                for r in state.blocked_ips[:6]] or ["(none yet)"]
    lines += _box("ATTACKER IPs", ip_lines, width)
    patch_lines = [f"{(p.get('path') or '?'):<44} {'(dry-run)' if p.get('dry_run') else 'APPLIED'}"
                   for p in state.applied_patches[:6]] or ["(none yet)"]
    lines += _box("PATCHES", patch_lines, width)

    return "\n".join(lines)
