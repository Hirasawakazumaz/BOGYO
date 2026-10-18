"""Aggregate the live defense picture from the audit log, usage, and geo.

Pure/offline by default (geo lookups only run when enabled in settings). The
Textual app and the plain CLI snapshot both render a :class:`DashboardState`.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from ..core.config import Settings
from ..intel.geo import country_centroid, lookup_ip
from ..usage.governor import Governor, GovernorState
from ..usage.ledger import UsageLedger
from .worldmap import Marker


@dataclass
class DashboardState:
    home_country: str
    home_label: str
    home_latlon: Optional[tuple[float, float]]
    attackers: list[Marker] = field(default_factory=list)
    blocked_ips: list[dict] = field(default_factory=list)      # {ip, country, blocked}
    applied_patches: list[dict] = field(default_factory=list)  # {path, host, dry_run}
    proposed_patches: int = 0
    vuln_count: int = 0
    breaches: int = 0
    allows: int = 0
    denies: int = 0
    tests: Optional[dict] = None                               # {passed, failed, total}
    usage: Optional[GovernorState] = None
    audit_intact: bool = True


def _iter_audit(path: Path):
    if not path.exists():
        return
    prev = "0" * 64
    ok = True
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            e = json.loads(line)
        except json.JSONDecodeError:
            ok = False
            continue
        yield e, (e.get("prev") == prev)
        prev = e.get("hash", prev)


class DashboardModel:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings

    def build(self) -> DashboardState:
        s = self.settings
        home_latlon = country_centroid(s.geo.home_country)
        state = DashboardState(
            home_country=s.geo.home_country,
            home_label=s.geo.home_label,
            home_latlon=home_latlon,
        )

        blocked_seen: dict[str, dict] = {}
        patches: list[dict] = []
        vulns = 0
        audit_intact = True
        for e, chain_ok in _iter_audit(Path(s.paths.audit_file)):
            if not chain_ok:
                audit_intact = False
            ev = e.get("event", "")
            data = e.get("data", {})
            if ev == "authorize.allow":
                state.allows += 1
            elif ev == "authorize.deny":
                state.denies += 1
            elif ev in ("block.apply", "block.plan"):
                ip = data.get("ip")
                if ip:
                    # applied => truly blocked (x); planned/dry-run => still active (!)
                    blocked_seen[ip] = {"ip": ip, "blocked": ev == "block.apply"}
            elif ev in ("patch.apply", "patch.apply.plan"):
                patches.append({"path": data.get("path"), "host": data.get("host"), "dry_run": ev.endswith(".plan")})
            elif ev in ("patch.propose",):
                state.proposed_patches += int(data.get("candidates", 0))
            elif ev == "cve.lookup":
                vulns += int(data.get("found", 0))
            elif ev == "sandbox.validate" and data.get("breached"):
                state.breaches += 1

        state.audit_intact = audit_intact
        state.vuln_count = vulns
        state.applied_patches = patches

        # Geolocate blocked IPs (only if enabled; offline -> no marker, still listed).
        for ip, rec in blocked_seen.items():
            geo = lookup_ip(ip, s.geo)
            rec["country"] = geo.country_code if geo.ok else "??"
            state.blocked_ips.append(rec)
            if geo.ok and geo.lat is not None and geo.lon is not None:
                state.attackers.append(Marker(lat=geo.lat, lon=geo.lon, blocked=rec["blocked"], label=geo.country_code))

        # Test status (optional cache written by `sentinel selftest`).
        tp = Path(s.paths.state_dir) / "test-status.json"
        if tp.exists():
            try:
                state.tests = json.loads(tp.read_text(encoding="utf-8"))
            except json.JSONDecodeError:
                state.tests = None

        # Usage governor snapshot.
        gov = Governor(s.usage, UsageLedger(s.paths.usage_file))
        state.usage = gov.state()
        return state
