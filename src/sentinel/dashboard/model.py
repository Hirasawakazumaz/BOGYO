"""Aggregate the live defense picture from the audit log, usage, and geo.

Pure/offline by default (geo lookups only run when enabled in settings). The
Textual app and the plain CLI snapshot both render a :class:`DashboardState`.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional

ATTACK_BINS = 24
ATTACK_BUCKET_SECONDS = 15


def _short(data: dict) -> str:
    for k in ("ip", "target", "path", "replica", "host", "finding"):
        if data.get(k):
            return str(data[k])
    return ""


def _parse_ts(ts: str) -> Optional[datetime]:
    try:
        return datetime.fromisoformat(ts)
    except (ValueError, TypeError):
        return None


def _bucketize(times: list[datetime]) -> list[int]:
    """Counts of block events over the last ATTACK_BINS windows (old -> new)."""
    if not times:
        return [0] * ATTACK_BINS
    now = max(times[-1], datetime.now(times[-1].tzinfo))
    series = [0] * ATTACK_BINS
    span = ATTACK_BINS * ATTACK_BUCKET_SECONDS
    for t in times:
        age = (now - t).total_seconds()
        if 0 <= age < span:
            idx = ATTACK_BINS - 1 - int(age // ATTACK_BUCKET_SECONDS)
            if 0 <= idx < ATTACK_BINS:
                series[idx] += 1
    return series

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
    language: str = "en"
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
    # settings snapshot for the analysis panel
    dry_run: bool = True
    toggles: dict = field(default_factory=dict)
    limits: dict = field(default_factory=dict)
    model_tiers: list = field(default_factory=list)
    # live activity
    current_activity: str = "idle"                             # event name (mapped to i18n)
    current_detail: str = ""
    recent_logs: list[str] = field(default_factory=list)       # formatted lines, newest last
    pending_patches: list[dict] = field(default_factory=list)  # proposed, not yet applied
    attack_series: list[int] = field(default_factory=list)     # blocks per time bucket (old->new)


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
            language=s.ui.language,
            dry_run=s.dry_run,
            toggles=s.toggles.model_dump(),
            limits=s.limits.model_dump(),
            model_tiers=list(s.usage.model_tiers),
        )

        blocked_seen: dict[str, dict] = {}
        patches: list[dict] = []
        proposed: list[dict] = []
        applied_paths: set[str] = set()
        vulns = 0
        audit_intact = True
        block_times: list[datetime] = []
        recent: list[str] = []
        last_event: tuple[str, dict] = ("", {})
        for e, chain_ok in _iter_audit(Path(s.paths.audit_file)):
            if not chain_ok:
                audit_intact = False
            ev = e.get("event", "")
            data = e.get("data", {})
            ts = e.get("ts", "")
            last_event = (ev, data)
            recent.append(f"{ts[11:19]} {ev} {_short(data)}")
            if ev == "authorize.allow":
                state.allows += 1
            elif ev == "authorize.deny":
                state.denies += 1
            elif ev in ("block.apply", "block.plan"):
                ip = data.get("ip")
                if ip:
                    blocked_seen[ip] = {"ip": ip, "blocked": ev == "block.apply"}
                dt = _parse_ts(ts)
                if dt:
                    block_times.append(dt)
            elif ev in ("patch.apply", "patch.apply.plan"):
                path = data.get("path")
                patches.append({"path": path, "host": data.get("host"), "dry_run": ev.endswith(".plan")})
                if path:
                    applied_paths.add(path)
            elif ev == "patch.propose":
                n = int(data.get("candidates", 0))
                state.proposed_patches += n
                if n:
                    proposed.append({"finding": data.get("finding", "?"), "service": data.get("service", "?"),
                                     "path": data.get("path"), "candidates": n})
            elif ev == "cve.lookup":
                vulns += int(data.get("found", 0))
            elif ev == "sandbox.validate" and data.get("breached"):
                state.breaches += 1

        state.audit_intact = audit_intact
        state.vuln_count = vulns
        state.applied_patches = patches
        state.pending_patches = [p for p in proposed if not (p.get("path") and p["path"] in applied_paths)][-8:]
        state.recent_logs = recent[-10:]
        state.current_activity = last_event[0] or "idle"
        state.current_detail = _short(last_event[1])
        state.attack_series = _bucketize(block_times)

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
