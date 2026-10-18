"""Plain-text dashboard snapshot (no Textual needed) — used by `sentinel dashboard --once`.

Renders the CASIO-world-map / cyber panel as a single string so it works over any
terminal or in CI, and is easy to unit-test. The interactive Textual app reuses
the same :class:`DashboardState` and world map.
"""

from __future__ import annotations

from datetime import datetime

from ..i18n import t
from .model import DashboardState
from .worldmap import ATK_ACTIVE, ATK_BLOCKED, HOME, W, render_grid

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
    lang = state.language
    width = W + 4
    clock = datetime.now().astimezone().strftime("%Y-%m-%d %H:%M:%S %Z")
    lines: list[str] = []
    lines.append("")
    lines.append(t("app.title", lang).center(width))
    lines.append(f"{clock}".center(width))
    lines.append("")

    # world map
    grid = render_grid(state.home_latlon, state.attackers)
    home_tag = f"{state.home_label}({state.home_country})"
    map_title = (
        f"{t('panel.worldmap', lang)}  {HOME}={home_tag}  "
        f"{ATK_BLOCKED}={t('lbl.blocked', lang)}  {ATK_ACTIVE}={t('lbl.active', lang)}"
    )
    lines += _box(map_title, grid, width)

    # stats
    u = state.usage
    tests = state.tests or {}
    test_str = (f"{tests.get('passed','?')}/{tests.get('total','?')} {t('lbl.pass', lang)}"
                if state.tests else t("lbl.na", lang))
    audit_str = t("status.intact", lang) if state.audit_intact else t("status.tampered", lang)
    stat_lines = [
        f"{t('lbl.blocked_ips', lang)}: {len(state.blocked_ips):<4}  {t('lbl.breaches', lang)}: {state.breaches:<4}  {t('lbl.vulns', lang)}: {state.vuln_count:<4}",
        f"{t('lbl.authorizations', lang)}: allow {state.allows:<5} deny {state.denies:<5}  {t('lbl.tests', lang)}: {test_str}",
        f"{t('lbl.patches', lang)}: +{state.proposed_patches:<3} {t('lbl.applied', lang)} {len(state.applied_patches):<3}  {t('lbl.audit', lang)}: {audit_str}",
    ]
    lines += _box(t("panel.status", lang), stat_lines, width)

    # settings analysis (gauges + numbers)
    lines += _box(t("panel.analysis", lang), _analysis_lines(state, lang), width)

    # usage governor
    if u is not None:
        usage_lines = [
            f"{t('lbl.provider', lang)}: {u.provider:<4}  {t('lbl.level', lang)}: {u.level:<10}  {t('lbl.model', lang)}: {u.model}",
            f"{t('lbl.tokens_today', lang)}: {u.tokens_today:,} / {u.budget:,}  {u.bar(28)} {int(u.fraction*100)}%",
            f"{t('lbl.runs_per_hour', lang)}: {u.runs_per_hour:<4}  {t('lbl.run_allowed', lang)}: {'YES' if u.allow_run else t('lbl.stopped', lang)}  {t('lbl.resets', lang)}: {u.resets_at[:16]}",
        ]
        lines += _box(t("panel.usage", lang), usage_lines, width)

    # lists
    none_yet = t("lbl.none_yet", lang)
    ip_lines = [f"{r['ip']:<40} {r.get('country','??'):<4} {t('lbl.blocked', lang) if r['blocked'] else t('lbl.seen', lang)}"
                for r in state.blocked_ips[:6]] or [none_yet]
    lines += _box(t("panel.ips", lang), ip_lines, width)
    patch_lines = [f"{(p.get('path') or '?'):<44} {t('lbl.dry_run_short', lang) if p.get('dry_run') else t('lbl.applied', lang)}"
                   for p in state.applied_patches[:6]] or [none_yet]
    lines += _box(t("panel.patches", lang), patch_lines, width)

    return "\n".join(lines)


def _indicator(on: bool) -> str:
    return "●" if on else "○"


def _analysis_lines(state: DashboardState, lang: str) -> list[str]:
    tg = state.toggles
    lim = state.limits
    on, off = t("lbl.enabled", lang), t("lbl.disabled", lang)
    caps = (
        f"{_indicator(tg.get('enable_blocking'))} {t('cap.blocking', lang)}   "
        f"{_indicator(tg.get('enable_active_scan'))} {t('cap.active_scan', lang)}   "
        f"{_indicator(tg.get('enable_sandbox_redteam'))} {t('cap.sandbox_redteam', lang)}   "
        f"{_indicator(tg.get('enable_patch_apply'))} {t('cap.patch_apply', lang)}"
    )
    window = lim.get("time_window") or t("lbl.anytime", lang)
    limits = (
        f"{t('lbl.max_targets', lang)}={lim.get('max_targets_per_run','?')}  "
        f"{t('lbl.rate', lang)}={lim.get('rate_per_minute','?')}  "
        f"{t('lbl.concurrency', lang)}={lim.get('max_concurrency','?')}  "
        f"{t('lbl.window', lang)}={window}"
    )
    tiers = " → ".join(state.model_tiers) if state.model_tiers else "-"
    return [
        f"{t('lbl.dry_run', lang)}: {on if state.dry_run else off}     {t('lbl.capabilities', lang)}:",
        f"  {caps}",
        f"{t('lbl.limits', lang)}: {limits}",
        f"{t('lbl.model_tiers', lang)}: {tiers}",
    ]
