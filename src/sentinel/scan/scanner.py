"""Scan orchestration over standard, legitimate tools (nmap, nuclei).

The scanner only *builds and runs* existing tools against in-scope hosts; it
contains no exploit code of its own. Every scan is authorized as
``ActionClass.ACTIVE_SCAN`` and is a no-op (command returned only) in dry-run.
"""

from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass
from typing import Optional

from ..core.actions import ActionClass
from ..guards import ScopeGuard


@dataclass(frozen=True)
class ScanPlan:
    target: str
    tool: str
    command: list[str]
    dry_run: bool
    output: Optional[str] = None
    returncode: Optional[int] = None


class Scanner:
    #: tool -> argv builder (target is injected). Low-intensity defaults.
    BUILDERS = {
        "nmap": lambda t: ["nmap", "-sV", "-T2", "--open", t],
        "nuclei": lambda t: ["nuclei", "-silent", "-u", t],
    }

    def __init__(self, guard: ScopeGuard, runner=None) -> None:
        self.guard = guard
        self._runner = runner or self._default_runner

    @staticmethod
    def _default_runner(args: list[str], timeout: int) -> tuple[int, str]:
        proc = subprocess.run(
            args, capture_output=True, text=True, timeout=timeout, check=False
        )
        return proc.returncode, (proc.stdout + proc.stderr)

    def scan(self, target: str, tool: str = "nmap") -> ScanPlan:
        if tool not in self.BUILDERS:
            raise ValueError(f"unsupported tool {tool!r}; choose from {list(self.BUILDERS)}")
        decision = self.guard.authorize(ActionClass.ACTIVE_SCAN, target=target)
        command = self.BUILDERS[tool](target)

        if decision.dry_run:
            self.guard.audit.append("scan.plan", {"target": target, "tool": tool, "command": command})
            return ScanPlan(target, tool, command, dry_run=True)

        if shutil.which(command[0]) is None:
            raise RuntimeError(f"{command[0]} not installed; stay in dry-run or install it")
        rc, out = self._runner(command, self.guard.settings.limits.scan_timeout_seconds)
        self.guard.audit.append("scan.run", {"target": target, "tool": tool, "rc": rc})
        return ScanPlan(target, tool, command, dry_run=False, output=out, returncode=rc)
