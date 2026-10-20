"""Plain-text dashboard snapshot (no Textual needed) — used by `sentinel dashboard --once`.

Renders the CASIO-world-map / cyber panel as a single string so it works over any
terminal or in CI, and is easy to unit-test. The interactive Textual app reuses
the same :class:`DashboardState` and world map.
"""

from __future__ import annotations

from datetime import datetime

from ..i18n import t
from .model import DashboardState

PANEL_W = 78
_TL, _TR, _BL, _BR, _H, _V = "╔", "╗", "╚", "╝", "═", "║"
_STAGES = ["intake", "scan", "sandbox", "propose", "eval", "apply"]
_SPINNER = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"


def _box(title: str, lines: list[str], width: int) -> list[str]:
    inner = width - 2
    top = f"{_TL}{_H} {title} ".ljust(width - 1, _H) + _TR
    out = [top]
    for ln in lines:
        out.append(f"{_V} " + ln[: inner - 2].ljust(inner - 2) + f" {_V}")
    out.append(f"{_BL}{_H * inner}{_BR}")
    return out


def render_snapshot(state: DashboardState, frame: int = 0) -> str:
    lang = state.language
    width = PANEL_W + 4
    clock = datetime.now().astimezone().strftime("%Y-%m-%d %H:%M:%S %Z")
    lines: list[str] = []
    lines.append("")
    lines.append(t("app.title", lang).center(width))
    lines.append(f"{clock}".center(width))
    lines.append("")

    # current activity + animated patch pipeline
    act = t(f"act.{state.current_activity}", lang)
    if act == f"act.{state.current_activity}":
        act = state.current_activity  # unknown event -> raw name
    detail = f"  →  {state.current_detail}" if state.current_detail else ""
    lines += _box(t("panel.activity", lang), [f"▶ {act}{detail}"], width)
    lines += _box(t("panel.pipeline", lang), pipeline_lines(state.pipeline_stage, frame, lang), width)

    # docker sandbox (attack validation) + attack graph
    lines += _box(t("panel.sandbox", lang), _sandbox_lines(state, lang), width)
    lines += _box(t("panel.attack_graph", lang), _attack_graph(state.attack_series, width - 6), width)

    # security block stats
    lines += _box(t("panel.blockstats", lang), [
        f"{t('lbl.today', lang)}: {state.blocks_today:<6} {t('lbl.month', lang)}: {state.blocks_month:<6} "
        f"IP: {len(state.blocked_ips)}"
    ], width)

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

    # pending patches (proposed, awaiting apply)
    pend_lines = [f"{p.get('service','?'):<10} {p.get('finding','?'):<12} x{p.get('candidates',1)}"
                  for p in state.pending_patches[:6]] or [none_yet]
    lines += _box(t("panel.pending", lang), pend_lines, width)

    # live log tail
    log_lines = list(state.recent_logs[-8:]) or [none_yet]
    lines += _box(t("panel.logs", lang), log_lines, width)

    return "\n".join(lines)


def pipeline_lines(stage: str, frame: int, lang: str) -> list[str]:
    """Animated patch-creation pipeline: ✓ done · future, spinner on active stage,
    plus a moving flow marker for an 'anime' feel (frame advances each tick)."""
    active = _STAGES.index(stage) if stage in _STAGES else -1
    spin = _SPINNER[frame % len(_SPINNER)]
    parts = []
    for i, st in enumerate(_STAGES):
        if active < 0:
            mark = "·"
        elif i < active:
            mark = "✓"
        elif i == active:
            mark = spin
        else:
            mark = "·"
        parts.append(f"{mark} {t('stage.' + st, lang)}")
    track = 52
    pos = frame % track if active >= 0 else 0
    flow = "·" * pos + "►" + "·" * (track - pos - 1) if active >= 0 else "·" * track
    return ["   ".join(parts), flow]


def _sandbox_lines(state: DashboardState, lang: str) -> list[str]:
    if not state.sandbox_recent:
        return [t("sandbox.idle", lang)]
    out = []
    for v in state.sandbox_recent[-6:]:
        status = (t("sandbox.planned", lang) if v.get("planned")
                  else t("sandbox.breach", lang) if v.get("breached")
                  else t("sandbox.clean", lang))
        out.append(f"{v.get('name','?'):<16} @ {v.get('replica','?'):<16} [{status}]")
    return out


_SPARK = "▁▂▃▄▅▆▇█"


def _attack_graph(series: list[int], span: int) -> list[str]:
    s = (series or [0])[-span:]
    peak = max(s) if s else 0
    if peak <= 0:
        return ["▁" * len(s) + f"   peak 0"]
    bars = "".join(_SPARK[min(len(_SPARK) - 1, int(v / peak * (len(_SPARK) - 1)))] for v in s)
    return [bars, f"peak {peak}/bucket   total {sum(s)}"]


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
