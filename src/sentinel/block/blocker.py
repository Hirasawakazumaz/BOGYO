"""Firewall blocker built on an nftables dynamic set with per-entry timeout (TTL).

Purely defensive: it installs a *drop* rule for inbound packets from an attacking
source IP. It never sends traffic back to the attacker (no hack-back).

Every block goes through the guard (``ActionClass.BLOCK``). In dry-run mode the
nft command is returned/recorded instead of executed, so you can see exactly what
would happen before enabling it for real.
"""

from __future__ import annotations

import ipaddress
import shutil
import subprocess
from dataclasses import dataclass
from typing import Optional

from ..core.actions import ActionClass
from ..guards import ScopeGuard

TABLE = "inet sentinel_guard"
SET_V4 = "blocked_v4"
SET_V6 = "blocked_v6"


@dataclass(frozen=True)
class BlockResult:
    ip: str
    ttl_seconds: int
    command: str
    executed: bool
    dry_run: bool


class FirewallBlocker:
    """nftables-backed blocker. Pass ``runner`` to inject a fake for tests."""

    def __init__(self, guard: ScopeGuard, runner=None) -> None:
        self.guard = guard
        self._runner = runner or self._default_runner

    @staticmethod
    def _default_runner(args: list[str]) -> int:
        return subprocess.run(args, check=False).returncode

    # -- nft command construction ------------------------------------------- #
    @staticmethod
    def _add_command(ip: str, ttl_seconds: int) -> str:
        addr = ipaddress.ip_address(ip)
        set_name = SET_V6 if addr.version == 6 else SET_V4
        # `add element` with a timeout gives us an automatic TTL expiry.
        return f"nft add element {TABLE} {set_name} {{ {ip} timeout {ttl_seconds}s }}"

    # -- public API --------------------------------------------------------- #
    def block_ip(self, ip: str, ttl_seconds: int = 3600) -> BlockResult:
        """Authorize, then block (or simulate blocking) an inbound source IP."""
        ipaddress.ip_address(ip)  # validate; raises ValueError on garbage
        decision = self.guard.authorize(ActionClass.BLOCK, target=ip)
        command = self._add_command(ip, ttl_seconds)

        if decision.dry_run:
            self.guard.audit.append(
                "block.plan", {"ip": ip, "ttl": ttl_seconds, "command": command}
            )
            return BlockResult(ip, ttl_seconds, command, executed=False, dry_run=True)

        if shutil.which("nft") is None:
            raise RuntimeError("nft binary not found; install nftables or stay in dry-run")
        rc = self._runner(command.split())
        executed = rc == 0
        self.guard.audit.append(
            "block.apply",
            {"ip": ip, "ttl": ttl_seconds, "command": command, "rc": rc},
        )
        if not executed:
            raise RuntimeError(f"nft command failed (rc={rc}): {command}")
        return BlockResult(ip, ttl_seconds, command, executed=True, dry_run=False)

    @staticmethod
    def ensure_table_commands() -> list[str]:
        """Commands an operator runs once (as root) to create the table/sets/chain."""
        return [
            f"nft add table {TABLE}",
            f"nft add set {TABLE} {SET_V4} {{ type ipv4_addr; flags timeout; }}",
            f"nft add set {TABLE} {SET_V6} {{ type ipv6_addr; flags timeout; }}",
            f"nft add chain {TABLE} input {{ type filter hook input priority -150; }}",
            f"nft add rule {TABLE} input ip saddr @{SET_V4} drop",
            f"nft add rule {TABLE} input ip6 saddr @{SET_V6} drop",
        ]
