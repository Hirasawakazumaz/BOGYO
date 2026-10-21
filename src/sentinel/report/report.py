"""Run reports (Markdown + JSON) built from the audit log only.

The reporter is a pure reader: it parses the hash-chained audit log (and verifies
its integrity) and tallies what happened — authorizations allowed/denied, scans,
blocks, sandbox validations (breaches), patch proposals and any applied changes.
It performs no active operation and needs no guard.
"""

from __future__ import annotations

import json
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

from ..core.audit import AuditLog


@dataclass
class RunReport:
    audit_file: str
    chain_intact: bool
    total_events: int
    event_counts: dict[str, int]
    allowed: int
    denied: int
    denied_reasons: list[dict[str, Any]]
    scans: int
    blocks_applied: int
    blocks_planned: int
    breaches: int
    validations: int
    patches_proposed: int
    patches_applied: int
    applied_changes: list[dict[str, Any]] = field(default_factory=list)

    def to_json(self) -> str:
        return json.dumps(self.__dict__, indent=2, ensure_ascii=False, sort_keys=True)

    def to_markdown(self) -> str:
        integ = "intact ✅" if self.chain_intact else "TAMPERED ❌"
        lines = [
            "# SAKI-MORI run report",
            "",
            f"- audit log: `{self.audit_file}`",
            f"- chain integrity: **{integ}**",
            f"- total events: {self.total_events}",
            "",
            "## Breach tally",
            "",
            f"- sandbox validations run: **{self.validations}**",
            f"- findings confirmed (breached in sandbox): **{self.breaches}**",
            "",
            "## Authorizations",
            "",
            f"- allowed: {self.allowed}",
            f"- denied (fail-closed): {self.denied}",
        ]
        if self.denied_reasons:
            lines.append("")
            lines.append("### Denied actions")
            lines.append("")
            for d in self.denied_reasons:
                lines.append(
                    f"- `{d.get('action')}` → {d.get('target')} — {d.get('error')}: {d.get('reason')}"
                )
        lines += [
            "",
            "## Defensive & remediation activity",
            "",
            f"- active scans: {self.scans}",
            f"- blocks applied / planned: {self.blocks_applied} / {self.blocks_planned}",
            f"- patches proposed: {self.patches_proposed}",
            f"- patches applied to hosts: {self.patches_applied}",
        ]
        if self.applied_changes:
            lines.append("")
            lines.append("### Applied changes")
            lines.append("")
            for c in self.applied_changes:
                lines.append(f"- {c.get('event')}: {json.dumps(c.get('data', {}), ensure_ascii=False)}")
        lines.append("")
        lines.append("## Analysis")
        lines.append("")
        lines.append(self._analysis())
        lines.append("")
        return "\n".join(lines)

    def _analysis(self) -> str:
        if not self.chain_intact:
            return (
                "⚠️ The audit chain failed verification — the log may have been "
                "tampered with. Treat every tally below as untrusted and investigate."
            )
        parts = []
        if self.breaches:
            parts.append(
                f"{self.breaches} finding(s) were confirmed exploitable in the isolated "
                "sandbox and should be prioritized for patching."
            )
        else:
            parts.append("No findings were confirmed exploitable in the sandbox this run.")
        if self.patches_proposed and not self.patches_applied:
            parts.append(
                f"{self.patches_proposed} hardening patch(es) were proposed but none applied "
                "— review the diffs and apply with approval."
            )
        if self.denied:
            parts.append(
                f"{self.denied} action(s) were refused by the guard (fail-closed); this is "
                "expected whenever a capability is disabled or a target is out of scope."
            )
        return " ".join(parts)


class ReportBuilder:
    def __init__(self, audit_file: str | Path) -> None:
        self.audit_file = Path(audit_file)

    def _entries(self) -> list[dict[str, Any]]:
        if not self.audit_file.exists():
            return []
        out = []
        for line in self.audit_file.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line:
                out.append(json.loads(line))
        return out

    def build(self) -> RunReport:
        entries = self._entries()
        counts = Counter(e.get("event", "?") for e in entries)
        allowed = counts.get("authorize.allow", 0)
        denied = counts.get("authorize.deny", 0)
        denied_reasons = [e["data"] for e in entries if e.get("event") == "authorize.deny"]

        breaches = sum(
            1
            for e in entries
            if e.get("event") == "sandbox.validate" and e.get("data", {}).get("breached")
        )
        validations = counts.get("sandbox.validate", 0) + counts.get("sandbox.validate.plan", 0)

        applied_changes = [
            {"event": e["event"], "data": e.get("data", {})}
            for e in entries
            if e.get("event") in ("block.apply", "patch.apply")
        ]

        chain_intact = AuditLog(self.audit_file).verify_chain()

        return RunReport(
            audit_file=str(self.audit_file),
            chain_intact=chain_intact,
            total_events=len(entries),
            event_counts=dict(counts),
            allowed=allowed,
            denied=denied,
            denied_reasons=denied_reasons,
            scans=counts.get("scan.run", 0) + counts.get("scan.plan", 0),
            blocks_applied=counts.get("block.apply", 0),
            blocks_planned=counts.get("block.plan", 0),
            breaches=breaches,
            validations=validations,
            patches_proposed=counts.get("patch.propose", 0),
            patches_applied=counts.get("patch.apply", 0),
            applied_changes=applied_changes,
        )

    def write(self, md_path: Optional[str | Path] = None, json_path: Optional[str | Path] = None) -> RunReport:
        report = self.build()
        if md_path is not None:
            p = Path(md_path)
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(report.to_markdown(), encoding="utf-8")
        if json_path is not None:
            p = Path(json_path)
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(report.to_json(), encoding="utf-8")
        return report
