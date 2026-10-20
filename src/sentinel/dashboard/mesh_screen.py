"""Mesh / network screen: this node, its peers (your own servers), an ASCII
topology diagram, and the patch-chain state. Opened with 'm' from the dashboard.
"""

from __future__ import annotations

from textual.app import ComposeResult
from textual.containers import VerticalScroll
from textual.screen import Screen
from textual.widgets import Footer, Header, Label, Static

from ..core.config import Settings
from ..i18n import t
from ..mesh import PatchChain


def topology(node_name: str, domain: str, peers: list) -> str:
    """A simple star topology: this node in the center, peers linked around it."""
    me = f"[{node_name or 'this'}:{domain or '-'}]"
    if not peers:
        return f"        {me}\n        (no peers)"
    lines = [f"              {me}"]
    lines.append("            /   |   \\")
    row = "   ".join(f"[{p.name}:{p.domain or '-'}]" for p in peers[:4])
    lines.append("   " + row)
    if len(peers) > 4:
        lines.append("   " + "   ".join(f"[{p.name}]" for p in peers[4:8]))
    return "\n".join(lines)


class MeshScreen(Screen):
    def __init__(self, settings_path: str) -> None:
        super().__init__()
        self.settings = Settings.load(settings_path)
        self.lang = self.settings.ui.language
        self.BINDINGS = [("escape", "app.pop_screen", t("cfg.back", self.lang))]

    def compose(self) -> ComposeResult:
        L = self.lang
        mc = self.settings.mesh
        yield Header(show_clock=True)
        with VerticalScroll(classes="panel"):
            yield Label(t("panel.mesh", L), classes="title")
            yield Label(f"{t('mesh.node', L)}: {mc.node_name or '-'}   {t('mesh.domain', L)}: {mc.domain or '-'}   "
                        f"{'●' if mc.enabled else '○'} {t('mesh.online', L) if mc.enabled else t('mesh.offline', L)}")
            yield Label(f"{t('mesh.peers', L)}: {len(mc.peers)}" if mc.peers else t("mesh.none", L))

            yield Label(f"── {t('mesh.topology', L)} ──", classes="title")
            yield Static(topology(mc.node_name, mc.domain, mc.peers), classes="panel")

            chain = PatchChain(mc.chain_file)
            yield Label(f"── {t('mesh.chain', L)} ──", classes="title")
            yield Label(f"{t('mesh.height', L)}: {chain.height()}   "
                        f"{t('mesh.pending_share', L)}: {len(chain.pending())}   "
                        f"{t('mesh.verified', L)}: {len(chain.applied())}")
        yield Footer()
