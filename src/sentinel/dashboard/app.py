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
from .model import DashboardModel
from .worldmap import ATK_ACTIVE, ATK_BLOCKED, HOME, LAND, render_grid

_MAP_STYLE = {
    LAND: "grey37",
    HOME: "bold cyan",
    ATK_BLOCKED: "bold red",
    ATK_ACTIVE: "bold yellow",
    "-": "red", "|": "red", "/": "red", "\\": "red",
}

CYBER_CSS = """
Screen { background: #04120a; color: #39ff14; }
#map { color: #39ff14; background: #04120a; border: round #0fae6e; padding: 0 1; }
.panel { border: round #0fae6e; background: #04120a; color: #7CFFb0; height: auto; }
.title { color: #00e0ff; text-style: bold; }
#statusbar { color: #00e0ff; }
Button { background: #0b3; color: #04120a; }
Input { background: #06230f; color: #39ff14; border: tall #0fae6e; }
Switch { background: #06230f; }
"""


def _map_text(state) -> Text:
    grid = render_grid(state.home_latlon, state.attackers)
    txt = Text()
    for row in grid:
        for ch in row:
            style = _MAP_STYLE.get(ch, "")
            txt.append(ch, style=style)
        txt.append("\n")
    return txt


class ConfigScreen(Screen):
    BINDINGS = [("escape", "app.pop_screen", "Back")]

    def __init__(self, settings_path: str) -> None:
        super().__init__()
        self.settings_path = settings_path
        self.settings = Settings.load(settings_path)

    def compose(self) -> ComposeResult:
        s = self.settings
        yield Header(show_clock=True)
        with VerticalScroll(classes="panel"):
            yield Label("CONFIG", classes="title")
            yield Label("Home country (ISO-2)")
            yield Input(value=s.geo.home_country, id="home_country")
            yield Label("Home label")
            yield Input(value=s.geo.home_label, id="home_label")
            yield Label("Provider (api/cli)")
            yield Input(value=s.usage.provider, id="provider")
            yield Label("Daily token budget")
            yield Input(value=str(s.usage.daily_token_budget), id="budget")
            yield Label("Base runs/hour")
            yield Input(value=str(s.usage.base_runs_per_hour), id="rph")
            with Horizontal():
                yield Label("dry_run")
                yield Switch(value=s.dry_run, id="dry_run")
            with Horizontal():
                yield Label("enable_geo_lookup")
                yield Switch(value=s.geo.enable_geo_lookup, id="geo")
            with Horizontal():
                yield Label("enable_blocking")
                yield Switch(value=s.toggles.enable_blocking, id="blk")
            with Horizontal():
                yield Label("enable_active_scan")
                yield Switch(value=s.toggles.enable_active_scan, id="scan")
            yield Button("SAVE", id="save")
            yield Label("", id="msg")
        yield Footer()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id != "save":
            return
        s = self.settings
        try:
            s.geo.home_country = self.query_one("#home_country", Input).value.strip().upper()[:2]
            s.geo.home_label = self.query_one("#home_label", Input).value.strip()
            s.usage.provider = self.query_one("#provider", Input).value.strip() or "api"
            s.usage.daily_token_budget = int(self.query_one("#budget", Input).value or 0)
            s.usage.base_runs_per_hour = max(1, int(self.query_one("#rph", Input).value or 1))
            s.dry_run = self.query_one("#dry_run", Switch).value
            s.geo.enable_geo_lookup = self.query_one("#geo", Switch).value
            s.toggles.enable_blocking = self.query_one("#blk", Switch).value
            s.toggles.enable_active_scan = self.query_one("#scan", Switch).value
            s.save(self.settings_path)
            self.query_one("#msg", Label).update("saved ✓")
        except (ValueError, OSError) as exc:
            self.query_one("#msg", Label).update(f"error: {exc}")


class SentinelDashboardApp(App):
    CSS = CYBER_CSS
    BINDINGS = [
        ("q", "quit", "Quit"),
        ("r", "refresh", "Refresh"),
        ("c", "config", "Config"),
    ]

    def __init__(self, settings_path: str, refresh_interval: float = 5.0) -> None:
        super().__init__()
        self.settings_path = settings_path
        self.refresh_interval = refresh_interval

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        yield Static(id="map", classes="panel")
        with Horizontal():
            yield Static(id="status", classes="panel")
            yield Static(id="usage", classes="panel")
        with Horizontal():
            yield Static(id="ips", classes="panel")
            yield Static(id="patches", classes="panel")
        yield Footer()

    def on_mount(self) -> None:
        self.title = "SENTINEL-GUARD // GLOBAL DEFENSE GRID"
        self.action_refresh()
        self.set_interval(self.refresh_interval, self.action_refresh)

    def action_config(self) -> None:
        self.push_screen(ConfigScreen(self.settings_path))

    def action_refresh(self) -> None:
        settings = Settings.load(self.settings_path)
        state = DashboardModel(settings).build()
        self.query_one("#map", Static).update(_map_text(state))
        u = state.usage
        tests = state.tests or {}
        self.query_one("#status", Static).update(
            f"[b cyan]DEFENSE STATUS[/]\n"
            f"blocked IPs : {len(state.blocked_ips)}\nbreaches    : {state.breaches}\n"
            f"vulns       : {state.vuln_count}\nallow/deny  : {state.allows}/{state.denies}\n"
            f"tests       : {tests.get('passed','?')}/{tests.get('total','?')}\n"
            f"audit       : {'INTACT' if state.audit_intact else 'TAMPERED'}"
        )
        if u:
            self.query_one("#usage", Static).update(
                f"[b cyan]USAGE GOVERNOR[/]\nprovider: {u.provider}  level: {u.level}\n"
                f"model   : {u.model}\ntokens  : {u.tokens_today:,}/{u.budget:,}\n"
                f"{u.bar(24)} {int(u.fraction*100)}%\nruns/hr : {u.runs_per_hour}  "
                f"run: {'YES' if u.allow_run else 'STOP'}\nresets  : {u.resets_at[:16]}"
            )
        self.query_one("#ips", Static).update(
            "[b cyan]ATTACKER IPs[/]\n" + ("\n".join(
                f"{r['ip']} {r.get('country','??')} {'BLK' if r['blocked'] else 'see'}"
                for r in state.blocked_ips[:8]) or "(none yet)")
        )
        self.query_one("#patches", Static).update(
            "[b cyan]PATCHES[/]\n" + ("\n".join(
                f"{(p.get('path') or '?')} {'(dry)' if p.get('dry_run') else 'APPLIED'}"
                for p in state.applied_patches[:8]) or "(none yet)")
        )
