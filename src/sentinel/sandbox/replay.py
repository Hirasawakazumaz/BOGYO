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
* A compose file is **parsed as YAML** (not string-matched) and refused unless
  every service attaches only to networks declared ``internal: true`` and no
  service opens an escape hatch (``privileged``, host namespaces, ``cap_add``,
  ``devices``, unconfined ``security_opt``, a docker-socket / host-path bind,
  or published ``ports``).
* ``--privileged`` and host-namespace/socket escalations are refused in every
  validation command too, and a validation command must be bound to the sandbox
  network/project so it cannot target an arbitrary host.
* ``dry_run`` (the default) returns the exact docker/compose commands and runs
  nothing — but all of the above checks still run so a plan can be refused.
* Bring-up and teardown are always recorded to the hash-chained audit log, and
  teardown runs even if a validation raises (context-manager / ``replay``).

The ``replica`` identifier must be an **in-scope, non-production** host id (the
host the sandbox reproduces); the guard enforces both.
"""

from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

import yaml

from ..core.actions import ActionClass
from ..core.errors import ModeViolation
from ..guards import ScopeGuard

#: Host paths a sandbox must never bind-mount (docker-socket escape, host FS).
_SENSITIVE_HOST_PATHS = (
    "/var/run/docker.sock",
    "/run/docker.sock",
    "/",
    "/etc",
    "/root",
    "/home",
    "/var/run",
    "/run",
    "/proc",
    "/sys",
    "/dev",
    "/boot",
    "/var/lib/docker",
)

#: CLI flags that share a host namespace when their value is ``host``.
_HOST_NS_FLAGS = {"--network", "--net", "--pid", "--ipc", "--uts", "--userns", "--cgroupns"}


def _is_sensitive_source(source: str) -> bool:
    """True if a bind-mount *host* source is the docker socket or a sensitive path."""
    s = (source or "").strip()
    if "docker.sock" in s:
        return True
    if not s.startswith("/"):
        return False  # named volume or project-relative path (./…) is fine
    s = s.rstrip("/") or "/"
    for p in _SENSITIVE_HOST_PATHS:
        pp = p.rstrip("/") or "/"
        if s == pp or s.startswith(pp + "/"):
            return True
    return False


def _is_sensitive_bind(spec: str) -> bool:
    """Short-form ``source:target[:mode]`` bind check."""
    return _is_sensitive_source(spec.split(":", 1)[0]) or "docker.sock" in spec


def _assert_no_escalation(tokens: list[str], where: str) -> None:
    """Refuse privilege/namespace/socket escalation in a raw command (fail closed).

    The *primary* defense for compose replicas is structural YAML analysis; this
    guards free-form validation/bring-up commands and catches ``--net=host`` and
    space-separated ``--network host`` variants.
    """
    def refuse(what: str) -> None:
        raise ModeViolation(f"refused {what} in sandbox {where}: capability escalation is not allowed")

    n = len(tokens)
    for i, tok in enumerate(tokens):
        nxt = tokens[i + 1] if i + 1 < n else ""
        if tok == "--privileged":
            refuse("--privileged")
        if tok == "--cap-add" or tok.startswith("--cap-add="):
            refuse("--cap-add")
        if tok == "--device" or tok.startswith("--device="):
            refuse("--device")
        if tok == "--security-opt" and "unconfined" in nxt:
            refuse(f"--security-opt {nxt}")
        if tok.startswith("--security-opt=") and "unconfined" in tok:
            refuse(tok)
        # host namespaces: --net=host / --network=host / --pid=host / ... (= form)
        if "=" in tok:
            flag, _, val = tok.partition("=")
            if flag in _HOST_NS_FLAGS and val == "host":
                refuse(tok)
        # space-separated form: --network host / --net host / --pid host / ...
        elif tok in _HOST_NS_FLAGS and nxt == "host":
            refuse(f"{tok} host")
        # docker-socket / sensitive bind mounts
        if tok in ("-v", "--volume", "--mount") and _is_sensitive_bind(nxt):
            refuse(f"bind mount {nxt!r}")
        if (tok.startswith("--volume=") or tok.startswith("-v=") or tok.startswith("--mount=")) and _is_sensitive_bind(
            tok.split("=", 1)[1]
        ):
            refuse(tok)
        if "docker.sock" in tok:
            refuse(tok)


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
            self._validate_compose_file(self.compose_file)

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
        self._assert_bound_to_sandbox(command)
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

    # -- F3: validations must be bound to this sandbox, not arbitrary hosts -- #
    def _assert_bound_to_sandbox(self, command: list[str]) -> None:
        joined = " ".join(command)
        refs_sandbox = (
            self.network in command
            or self.project in command
            or self.network in joined
            or self.project in joined
        )
        if not refs_sandbox:
            raise ModeViolation(
                f"refused validation command: it references neither the sandbox network "
                f"{self.network!r} nor the compose project {self.project!r}; validations must run "
                "inside the isolated sandbox, never against an arbitrary host"
            )
        # A `docker run`/`docker create` must explicitly attach to the internal net.
        if "docker" in command and ("run" in command or "create" in command):
            bound = False
            for i, tok in enumerate(command):
                nxt = command[i + 1] if i + 1 < len(command) else ""
                if tok in ("--network", "--net") and nxt == self.network:
                    bound = True
                if tok in (f"--network={self.network}", f"--net={self.network}"):
                    bound = True
            if not bound:
                raise ModeViolation(
                    f"refused docker run/create validation: must use --network {self.network} so it "
                    "runs inside the isolated, no-egress sandbox network"
                )

    # -- F1/F2: structural (YAML) analysis of the compose replica ------------ #
    def _validate_compose_file(self, path: str) -> None:
        """Parse the compose file and refuse any isolation hole (fail closed).

        Runs in dry-run too, so an unsafe plan is refused before anything starts.
        A missing file is skipped (dry-run may reference a not-yet-written file);
        a file that cannot be parsed is refused.
        """
        p = Path(path)
        if not p.exists():
            return
        try:
            doc = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
        except yaml.YAMLError as exc:
            raise ModeViolation(f"refused compose file {path!r}: cannot parse YAML ({exc})") from exc
        if not isinstance(doc, dict):
            raise ModeViolation(f"refused compose file {path!r}: top level is not a mapping")

        networks = doc.get("networks") or {}
        internal_nets: set[str] = set()
        if isinstance(networks, dict):
            for name, spec in networks.items():
                spec = spec or {}
                if isinstance(spec, dict) and spec.get("internal") is True and not spec.get("external"):
                    internal_nets.add(name)

        services = doc.get("services") or {}
        if not isinstance(services, dict) or not services:
            raise ModeViolation(f"refused compose file {path!r}: no services defined")
        for sname, svc in services.items():
            svc = svc or {}
            if not isinstance(svc, dict):
                raise ModeViolation(f"refused compose file {path!r}: service {sname!r} is not a mapping")
            self._check_service_escalation(path, sname, svc)
            self._check_service_isolation(path, sname, svc, internal_nets)

    @staticmethod
    def _check_service_escalation(path: str, sname: str, svc: dict[str, Any]) -> None:
        def refuse(what: str) -> None:
            raise ModeViolation(f"refused compose file {path!r}: service {sname!r} {what}")

        if svc.get("privileged") is True:
            refuse("sets privileged: true")
        nm = svc.get("network_mode")
        if nm is not None and nm != "none":
            refuse(f"sets network_mode: {nm!r} (only 'none' is allowed; use an internal network)")
        for key in ("pid", "ipc", "uts"):
            if svc.get(key) == "host":
                refuse(f"shares the host {key} namespace ({key}: host)")
        if svc.get("userns_mode") == "host":
            refuse("sets userns_mode: host")
        if svc.get("cgroup") == "host":
            refuse("sets cgroup: host")
        if svc.get("cap_add"):
            refuse(f"adds Linux capabilities (cap_add: {svc.get('cap_add')!r})")
        if svc.get("devices"):
            refuse("passes through host devices (devices:)")
        secopt = svc.get("security_opt") or []
        if isinstance(secopt, list):
            for s in secopt:
                if "unconfined" in str(s):
                    refuse(f"disables sandboxing confinement (security_opt: {s!r})")
        for vol in svc.get("volumes") or []:
            if isinstance(vol, str):
                if _is_sensitive_bind(vol):
                    refuse(f"bind-mounts a sensitive host path (volumes: {vol!r})")
            elif isinstance(vol, dict) and vol.get("type") == "bind":
                src = str(vol.get("source", ""))
                if _is_sensitive_source(src):
                    refuse(f"bind-mounts a sensitive host path (source: {src!r})")
        if svc.get("ports"):
            refuse("publishes ports to the host (ports:); the sandbox must stay internal")

    @staticmethod
    def _check_service_isolation(
        path: str, sname: str, svc: dict[str, Any], internal_nets: set[str]
    ) -> None:
        def refuse(what: str) -> None:
            raise ModeViolation(f"refused compose file {path!r}: service {sname!r} {what}")

        if svc.get("network_mode") == "none":
            return  # fully network-less: isolated
        nets = svc.get("networks")
        if nets is None:
            refuse(
                "declares no networks and would join the default bridge (egress); attach it only "
                "to a network declared internal: true"
            )
        if isinstance(nets, dict):
            names = list(nets.keys())
        elif isinstance(nets, list):
            names = list(nets)
        else:
            refuse(f"has an unrecognized networks: declaration ({nets!r})")
        if not names:
            refuse("declares an empty networks: list")
        for n in names:
            if n not in internal_nets:
                refuse(f"attaches to network {n!r}, which is not declared internal: true")
