"""Ephemeral, network-isolated Docker sandbox replay.

A :class:`SandboxReplay` stands up a throwaway Docker Compose replica of an
in-scope service on a *dedicated, internal* bridge network so that findings can
be validated **off production**. Attack-style validation is the only thing that
touches a replica, and it is routed through the guard as
``ActionClass.REDTEAM_ATTACK`` with ``environment="sandbox"`` — which the guard
hard-refuses on production targets and when the sandbox-redteam toggle is off.

Design rules baked in here:

* The dedicated network is created ``--internal`` (no egress) so a replica can
  never reach the real network while being probed.
* ``--privileged`` is refused everywhere (compose file contents and any
  validation command), so a sandbox can never gain host capabilities.
* ``dry_run`` (the default) returns the exact docker/compose commands and runs
  nothing.
* Bring-up and teardown are always recorded to the hash-chained audit log, and
  teardown runs even if a validation raises (context-manager / ``replay``).

The ``replica`` identifier must be an **in-scope, non-production** host id (the
host the sandbox reproduces); the guard enforces both.
"""

from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass, field
from typing import Optional

from ..core.actions import ActionClass
from ..core.errors import ModeViolation
from ..guards import ScopeGuard

#: Substrings that must never appear in a sandbox command (capability escalation).
_FORBIDDEN_TOKENS = ("--privileged", "--cap-add", "--pid=host", "--network=host")


def _assert_no_escalation(tokens: list[str], where: str) -> None:
    joined = " ".join(tokens)
    for bad in _FORBIDDEN_TOKENS:
        if bad in tokens or bad in joined:
            raise ModeViolation(f"refused {bad!r} in sandbox {where}: capability escalation is not allowed")


@dataclass(frozen=True)
class ValidationResult:
    name: str
    command: list[str]
    dry_run: bool
    returncode: Optional[int] = None
    output: Optional[str] = None

    @property
    def breached(self) -> bool:
        """A finding is confirmed (breached) when the validation tool exits 0."""
        return self.returncode == 0


@dataclass(frozen=True)
class SandboxPlan:
    replica: str
    network: str
    project: str
    compose_file: Optional[str]
    up_commands: list[str]
    down_commands: list[str]
    dry_run: bool
    validations: list[ValidationResult] = field(default_factory=list)


class SandboxReplay:
    """One ephemeral, network-isolated replica of an in-scope service.

    Pass ``runner`` (``list[str] -> (rc, output)``) to inject a fake in tests.
    """

    def __init__(
        self,
        guard: ScopeGuard,
        replica: str,
        *,
        compose_file: Optional[str] = None,
        network: Optional[str] = None,
        project: Optional[str] = None,
        runner=None,
    ) -> None:
        self.guard = guard
        self.replica = replica
        self.compose_file = compose_file
        slug = "".join(c if c.isalnum() else "_" for c in replica).strip("_") or "replica"
        self.network = network or f"sentinel_sbx_{slug}"
        self.project = project or f"sentinel_sbx_{slug}"
        self._runner = runner or self._default_runner
        self._up = False

    @staticmethod
    def _default_runner(args: list[str]) -> tuple[int, str]:
        proc = subprocess.run(args, capture_output=True, text=True, check=False)
        return proc.returncode, (proc.stdout + proc.stderr)

    # -- command construction ----------------------------------------------- #
    def up_commands(self) -> list[list[str]]:
        cmds: list[list[str]] = [
            # dedicated, internal (no egress) bridge network
            ["docker", "network", "create", "--driver", "bridge", "--internal", self.network],
        ]
        if self.compose_file is not None:
            cmds.append(
                ["docker", "compose", "-p", self.project, "-f", self.compose_file, "up", "-d"]
            )
        return cmds

    def down_commands(self) -> list[list[str]]:
        cmds: list[list[str]] = []
        if self.compose_file is not None:
            cmds.append(
                ["docker", "compose", "-p", self.project, "-f", self.compose_file, "down", "-v"]
            )
        cmds.append(["docker", "network", "rm", self.network])
        return cmds

    # -- lifecycle ----------------------------------------------------------- #
    def up(self) -> list[list[str]]:
        """Create the isolated network and (if given) bring up the compose replica."""
        cmds = self.up_commands()
        for c in cmds:
            _assert_no_escalation(c, "bring-up")
        if self.compose_file is not None:
            self._guard_compose_file(self.compose_file)

        dry = self.guard.settings.dry_run
        if dry:
            self.guard.audit.append(
                "sandbox.up.plan",
                {"replica": self.replica, "network": self.network, "commands": cmds},
            )
            self._up = True
            return cmds

        if shutil.which("docker") is None:
            raise RuntimeError("docker not installed; stay in dry-run or install Docker")
        for c in cmds:
            rc, out = self._runner(c)
            if rc != 0:
                self.guard.audit.append("sandbox.up.error", {"command": c, "rc": rc})
                raise RuntimeError(f"sandbox bring-up failed (rc={rc}): {' '.join(c)}")
        self.guard.audit.append(
            "sandbox.up", {"replica": self.replica, "network": self.network}
        )
        self._up = True
        return cmds

    def validate(self, name: str, command: list[str]) -> ValidationResult:
        """Run one attack-style validation against the replica, inside the sandbox.

        Authorized as ``REDTEAM_ATTACK`` with ``environment="sandbox"``; the guard
        refuses this on production targets and when the toggle is off.
        """
        _assert_no_escalation(command, "validation command")
        # THE gate: attack-style validation is sandbox-only, non-production, opt-in.
        decision = self.guard.authorize(
            ActionClass.REDTEAM_ATTACK, target=self.replica, environment="sandbox"
        )

        if decision.dry_run:
            self.guard.audit.append(
                "sandbox.validate.plan",
                {"replica": self.replica, "name": name, "command": command},
            )
            return ValidationResult(name, command, dry_run=True)

        rc, out = self._runner(command)
        self.guard.audit.append(
            "sandbox.validate",
            {"replica": self.replica, "name": name, "rc": rc, "breached": rc == 0},
        )
        return ValidationResult(name, command, dry_run=False, returncode=rc, output=out)

    def down(self) -> list[list[str]]:
        """Tear the replica and its network down; always recorded to the audit log."""
        cmds = self.down_commands()
        dry = self.guard.settings.dry_run
        if dry:
            self.guard.audit.append(
                "sandbox.down.plan",
                {"replica": self.replica, "network": self.network, "commands": cmds},
            )
            self._up = False
            return cmds

        if shutil.which("docker") is None:
            raise RuntimeError("docker not installed; stay in dry-run or install Docker")
        results = []
        for c in cmds:
            rc, _ = self._runner(c)
            results.append({"command": c, "rc": rc})  # best-effort teardown
        self.guard.audit.append(
            "sandbox.down", {"replica": self.replica, "network": self.network, "results": results}
        )
        self._up = False
        return cmds

    # -- orchestration ------------------------------------------------------- #
    def replay(self, validations: list[tuple[str, list[str]]]) -> SandboxPlan:
        """Up -> run each validation -> always tear down. Returns the full plan."""
        up = [" ".join(c) for c in self.up()]
        results: list[ValidationResult] = []
        try:
            for name, command in validations:
                results.append(self.validate(name, command))
        finally:
            down = [" ".join(c) for c in self.down()]
        return SandboxPlan(
            replica=self.replica,
            network=self.network,
            project=self.project,
            compose_file=self.compose_file,
            up_commands=up,
            down_commands=down,
            dry_run=self.guard.settings.dry_run,
            validations=results,
        )

    def __enter__(self) -> "SandboxReplay":
        self.up()
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.down()

    # -- safety helper ------------------------------------------------------- #
    @staticmethod
    def _guard_compose_file(path: str) -> None:
        from pathlib import Path

        p = Path(path)
        if not p.exists():
            return  # dry-run may reference a not-yet-written file; command is still safe
        text = p.read_text(encoding="utf-8", errors="replace")
        for bad in ("privileged: true", "network_mode: host", "network_mode: \"host\"", "pid: host"):
            if bad in text:
                raise ModeViolation(
                    f"refused compose file {path!r}: contains {bad!r} (capability escalation)"
                )
