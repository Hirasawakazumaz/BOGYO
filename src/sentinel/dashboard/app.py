"""Interactive Textual dashboard (loaded only via run_app; needs the [tui] extra).

A live "global defense grid": a colored world map with attacker->home arrows,
status/usage panels, and a config screen to edit settings from the TUI. Styling
is a green/cyan-on-black cyber / CASIO-world-map aesthetic.
"""

from __future__ import annotations

from datetime import datetime

from rich.text import Text
from textual.app import App, ComposeResult
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.screen import Screen
from textual.widgets import Button, Footer, Header, Input, Label, Static, Switch

from ..core.config import Settings
from ..i18n import t
from .model import DashboardModel
from .snapshot import _attack_graph, pipeline_lines

CYBER_CSS = """
Screen { background: #020a06; color: #39ff14; }
Header { background: #041a0e; color: #00e0ff; text-style: bold; }
Footer { background: #041a0e; color: #39ff14; }
#pipeline { color: #ffd500; background: #010704; border: round #0fae6e; padding: 0 1; height: auto; }
.panel { border: round #0b6; background: #04120a; color: #7CFFb0; height: auto; }
.wide { width: 1fr; }
.title { color: #00e0ff; text-style: bold; }
Button { background: #0c7; color: #021; text-style: bold; }
Input { background: #06230f; color: #39ff14; border: tall #0fae6e; }
Switch { background: #06230f; }
Label { color: #7CFFb0; }
"""


class ConfigScreen(Screen):
    def __init__(self, settings_path: str) -> None:
        super().__init__()
        self.settings_path = settings_path
        self.settings = Settings.load(settings_path)
        self.lang = self.settings.ui.language
        self.BINDINGS = [("escape", "app.pop_screen", t("cfg.back", self.lang))]

    def compose(self) -> ComposeResult:
        s = self.settings
        L = self.lang
        yield Header(show_clock=True)
        with VerticalScroll(classes="panel"):
            yield Label(t("panel.config", L), classes="title")
            yield Label(t("cfg.hint", L))

            yield Label(f"── {t('cfg.general', L)} ──", classes="title")
            with Horizontal():
                yield Label(t("cfg.dry_run", L)); yield Switch(value=s.dry_run, id="dry_run")
            yield Label(t("cfg.home_country", L)); yield Input(value=s.geo.home_country, id="home_country")
            yield Label(t("cfg.home_label", L)); yield Input(value=s.geo.home_label, id="home_label")
            with Horizontal():
                yield Label(t("cfg.geo_lookup", L)); yield Switch(value=s.geo.enable_geo_lookup, id="geo")

            yield Label(f"── {t('cfg.capabilities', L)} ──", classes="title")
            with Horizontal():
                yield Label(t("cap.blocking", L)); yield Switch(value=s.toggles.enable_blocking, id="blk")
            with Horizontal():
                yield Label(t("cap.active_scan", L)); yield Switch(value=s.toggles.enable_active_scan, id="scan")
            with Horizontal():
                yield Label(t("cap.sandbox_redteam", L)); yield Switch(value=s.toggles.enable_sandbox_redteam, id="rt")
            with Horizontal():
                yield Label(t("cap.patch_apply", L)); yield Switch(value=s.toggles.enable_patch_apply, id="pa")

            yield Label(f"── {t('cfg.usage', L)} ──", classes="title")
            yield Label(t("cfg.provider", L)); yield Input(value=s.usage.provider, id="provider")
            yield Label(t("cfg.daily_budget", L)); yield Input(value=str(s.usage.daily_token_budget), id="budget")
            yield Label(t("cfg.base_rph", L)); yield Input(value=str(s.usage.base_runs_per_hour), id="rph")
            yield Label(t("cfg.downgrade_at", L)); yield Input(value=str(s.usage.downgrade_at), id="dg")
            yield Label(t("cfg.throttle_at", L)); yield Input(value=str(s.usage.throttle_at), id="th")
            yield Label(t("cfg.stop_at", L)); yield Input(value=str(s.usage.stop_at), id="st")

            yield Label(f"── {t('cfg.limits', L)} ──", classes="title")
            yield Label(t("cfg.max_targets", L)); yield Input(value=str(s.limits.max_targets_per_run), id="mt")
            yield Label(t("cfg.rate", L)); yield Input(value=str(s.limits.rate_per_minute), id="rate")
            yield Label(t("cfg.concurrency", L)); yield Input(value=str(s.limits.max_concurrency), id="cc")
            yield Label(t("cfg.scan_timeout", L)); yield Input(value=str(s.limits.scan_timeout_seconds), id="to")
            yield Label(t("cfg.time_window", L)); yield Input(value=s.limits.time_window, id="tw")

            yield Button(t("cfg.save", L), id="save")
            yield Label("", id="msg")
        yield Footer()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id != "save":
            return
        s = self.settings
        q = self.query_one
        try:
            s.dry_run = q("#dry_run", Switch).value
            s.geo.home_country = q("#home_country", Input).value.strip().upper()[:2]
            s.geo.home_label = q("#home_label", Input).value.strip()
            s.geo.enable_geo_lookup = q("#geo", Switch).value
            s.toggles.enable_blocking = q("#blk", Switch).value
            s.toggles.enable_active_scan = q("#scan", Switch).value
            s.toggles.enable_sandbox_redteam = q("#rt", Switch).value
            s.toggles.enable_patch_apply = q("#pa", Switch).value
            s.usage.provider = q("#provider", Input).value.strip() or "api"
            s.usage.daily_token_budget = max(0, int(q("#budget", Input).value or 0))
            s.usage.base_runs_per_hour = max(1, int(q("#rph", Input).value or 1))
            s.usage.downgrade_at = float(q("#dg", Input).value)
            s.usage.throttle_at = float(q("#th", Input).value)
            s.usage.stop_at = float(q("#st", Input).value)
            s.limits.max_targets_per_run = max(1, int(q("#mt", Input).value or 1))
            s.limits.rate_per_minute = max(1, int(q("#rate", Input).value or 1))
            s.limits.max_concurrency = max(1, int(q("#cc", Input).value or 1))
            s.limits.scan_timeout_seconds = max(1, int(q("#to", Input).value or 1))
            s.limits.time_window = q("#tw", Input).value.strip()
            # validate as a whole, then persist
            Settings.model_validate(s.model_dump())
            s.save(self.settings_path)
            q("#msg", Label).update(t("cfg.saved", self.lang))
        except (ValueError, OSError) as exc:
            q("#msg", Label).update(f"error: {exc}")


class HelpScreen(Screen):
    def __init__(self, lang: str) -> None:
        super().__init__()
        self.lang = lang
        self.BINDINGS = [("escape", "app.pop_screen", t("cfg.back", lang))]

    def compose(self) -> ComposeResult:
        L = self.lang
        yield Header(show_clock=True)
        with VerticalScroll(classes="panel"):
            yield Label(t("panel.help", L), classes="title")
            for k in ("help.flow", "help.safety", "help.q", "help.r", "help.c", "help.h", "help.m"):
                yield Label(t(k, L))
        yield Footer()


class SentinelDashboardApp(App):
    CSS = CYBER_CSS
    BINDINGS = [
        ("q", "quit", "Quit"),
        ("r", "refresh", "Refresh"),
        ("c", "config", "Config"),
        ("h", "help", "Help"),
        ("m", "mesh", "Mesh"),
    ]

    def __init__(self, settings_path: str, refresh_interval: float = 3.0) -> None:
        super().__init__()
        self.settings_path = settings_path
        self.refresh_interval = refresh_interval
        self._frame = 0
        self._stage = ""
        self._lang = "en"

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        with Horizontal():
            yield Static(id="activity", classes="panel wide")
            yield Static(id="blockstats", classes="panel wide")
        yield Static(id="pipeline", classes="panel")
        with Horizontal():
            yield Static(id="sandbox", classes="panel wide")
            yield Static(id="attack", classes="panel wide")
        with Horizontal():
            yield Static(id="status", classes="panel")
            yield Static(id="usage", classes="panel")
        with Horizontal():
            yield Static(id="ips", classes="panel")
            yield Static(id="pending", classes="panel")
        with Horizontal():
            yield Static(id="patches", classes="panel")
            yield Static(id="logs", classes="panel")
        yield Footer()

    def on_mount(self) -> None:
        self.action_refresh()
        self.set_interval(self.refresh_interval, self.action_refresh)
        self.set_interval(0.2, self._animate)  # anime-style pipeline flow

    def _animate(self) -> None:
        self._frame += 1
        try:
            self.query_one("#pipeline", Static).update(
                f"[b cyan]{t('panel.pipeline', self._lang)}[/]\n[#ffd500]"
                + "\n".join(pipeline_lines(self._stage, self._frame, self._lang)) + "[/]"
            )
        except Exception:  # noqa: BLE001 - widget not mounted yet
            pass

    def action_config(self) -> None:
        self.push_screen(ConfigScreen(self.settings_path))

    def action_help(self) -> None:
        lang = Settings.load(self.settings_path).ui.language
        self.push_screen(HelpScreen(lang))

    def action_mesh(self) -> None:
        from .mesh_screen import MeshScreen
        self.push_screen(MeshScreen(self.settings_path))

    def action_refresh(self) -> None:
        settings = Settings.load(self.settings_path)
        state = DashboardModel(settings).build()
        lang = state.language
        self._lang = lang
        self._stage = state.pipeline_stage
        self.title = t("app.title", lang)
        u = state.usage
        tests = state.tests or {}
        none_yet = t("lbl.none_yet", lang)
        self.query_one("#status", Static).update(
            f"[b cyan]{t('panel.status', lang)}[/]\n"
            f"{t('lbl.blocked_ips', lang)} : {len(state.blocked_ips)}\n{t('lbl.breaches', lang)} : {state.breaches}\n"
            f"{t('lbl.vulns', lang)} : {state.vuln_count}\n{t('lbl.authorizations', lang)} : {state.allows}/{state.denies}\n"
            f"{t('lbl.tests', lang)} : {tests.get('passed','?')}/{tests.get('total','?')}\n"
            f"{t('lbl.audit', lang)} : {'INTACT' if state.audit_intact else 'TAMPERED'}"
        )
        if u:
            self.query_one("#usage", Static).update(
                f"[b cyan]{t('panel.usage', lang)}[/]\n{t('lbl.provider', lang)}: {u.provider}  {t('lbl.level', lang)}: {u.level}\n"
                f"{t('lbl.model', lang)}: {u.model}\n{t('lbl.tokens_today', lang)}: {u.tokens_today:,}/{u.budget:,}\n"
                f"{u.bar(24)} {int(u.fraction*100)}%\n{t('lbl.runs_per_hour', lang)}: {u.runs_per_hour}  "
                f"{t('lbl.run_allowed', lang)}: {'YES' if u.allow_run else 'STOP'}\n{t('lbl.resets', lang)}: {u.resets_at[:16]}"
            )
        self.query_one("#ips", Static).update(
            f"[b cyan]{t('panel.ips', lang)}[/]\n" + ("\n".join(
                f"{r['ip']} {r.get('country','??')} {'BLK' if r['blocked'] else 'see'}"
                for r in state.blocked_ips[:8]) or none_yet)
        )
        self.query_one("#patches", Static).update(
            f"[b cyan]{t('panel.patches', lang)}[/]\n" + ("\n".join(
                f"{(p.get('path') or '?')} {'(dry)' if p.get('dry_run') else 'APPLIED'}"
                for p in state.applied_patches[:8]) or none_yet)
        )
        # current activity
        act = t(f"act.{state.current_activity}", lang)
        if act == f"act.{state.current_activity}":
            act = state.current_activity
        detail = f"  →  {state.current_detail}" if state.current_detail else ""
        self.query_one("#activity", Static).update(
            f"[b cyan]{t('panel.activity', lang)}[/]\n[b #39ff14]▶ {act}[/]{detail}"
        )
        # attack graph
        graph = "\n".join(_attack_graph(state.attack_series, 40))
        self.query_one("#attack", Static).update(
            f"[b cyan]{t('panel.attack_graph', lang)}[/]\n[#ff6a00]{graph}[/]"
        )
        # pending patches
        self.query_one("#pending", Static).update(
            f"[b cyan]{t('panel.pending', lang)}[/]\n" + ("\n".join(
                f"{p.get('service','?')} {p.get('finding','?')} x{p.get('candidates',1)}"
                for p in state.pending_patches[:8]) or none_yet)
        )
        # live log
        self.query_one("#logs", Static).update(
            f"[b cyan]{t('panel.logs', lang)}[/]\n" + ("\n".join(state.recent_logs[-8:]) or none_yet)
        )
        # security block stats (today / month / unique IPs)
        self.query_one("#blockstats", Static).update(
            f"[b cyan]{t('panel.blockstats', lang)}[/]\n"
            f"[b #ff3355]{t('lbl.today', lang)}: {state.blocks_today}[/]   "
            f"{t('lbl.month', lang)}: {state.blocks_month}   IP: {len(state.blocked_ips)}"
        )
        # docker sandbox (attack validation)
        sb = state.sandbox_recent[-6:]
        sb_text = "\n".join(
            f"{v.get('name','?')} @ {v.get('replica','?')} "
            f"[{t('sandbox.planned', lang) if v.get('planned') else t('sandbox.breach', lang) if v.get('breached') else t('sandbox.clean', lang)}]"
            for v in sb) or t("sandbox.idle", lang)
        self.query_one("#sandbox", Static).update(
            f"[b cyan]{t('panel.sandbox', lang)}[/]\n{sb_text}"
        )
