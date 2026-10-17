"""Passive CVE lookup against the OSV.dev public database.

This only reads public vulnerability data for software versions you already know
you run; it sends nothing to your targets, so it is classified PASSIVE_READ.

Network and the ``requests`` dependency are optional: if either is unavailable,
the function returns an empty list rather than failing, keeping the core offline-
safe and testable.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from ..core.actions import ActionClass
from ..guards import ScopeGuard

OSV_URL = "https://api.osv.dev/v1/query"


@dataclass(frozen=True)
class Vuln:
    id: str
    summary: str


def lookup(guard: ScopeGuard, ecosystem: str, package: str, version: str) -> list[Vuln]:
    """Return known vulns for ``package@version``. Authorized as PASSIVE_READ."""
    guard.authorize(ActionClass.PASSIVE_READ, target=None)
    try:
        import requests  # optional dependency (extras: agent)
    except ImportError:
        guard.audit.append("cve.skip", {"reason": "requests not installed", "package": package})
        return []
    payload = {"version": version, "package": {"name": package, "ecosystem": ecosystem}}
    try:
        resp = requests.post(OSV_URL, json=payload, timeout=20)
        resp.raise_for_status()
        data = resp.json()
    except Exception as exc:  # noqa: BLE001 - network is best-effort here
        guard.audit.append("cve.error", {"package": package, "error": str(exc)})
        return []
    vulns = [
        Vuln(id=v.get("id", "?"), summary=v.get("summary", v.get("details", "")[:200]))
        for v in data.get("vulns", [])
    ]
    guard.audit.append("cve.lookup", {"package": package, "version": version, "found": len(vulns)})
    return vulns
