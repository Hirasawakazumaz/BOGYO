"""Generate systemd service+timer (and a cron fallback) for periodic defensive runs.

This module only *emits text*: the operator reviews it and installs it themselves
as root. The scheduled command is **defensive** (e.g. ``sentinel block`` /
``sentinel scan`` in dry-run); active red-team validation is never scheduled here
— it stays opt-in and sandbox-only, invoked deliberately. ``generate`` refuses to
build a unit whose command performs red-team / attack validation.
"""

from __future__ import annotations

import shlex
from dataclasses import dataclass

from ..core.errors import ModeViolation

#: Tokens that would indicate an attack-style scheduled run — refused.
_FORBIDDEN_SUBCOMMANDS = ("sandbox", "redteam", "attack")


@dataclass(frozen=True)
class ScheduleUnit:
    name: str
    command: str
    on_calendar: str
    service_text: str
    timer_text: str
    cron_line: str

    def describe(self) -> str:
        return (
            f"# --- /etc/systemd/system/{self.name}.service ---\n{self.service_text}\n"
            f"# --- /etc/systemd/system/{self.name}.timer ---\n{self.timer_text}\n"
            f"# --- cron fallback (crontab -e) ---\n{self.cron_line}\n"
        )


def _cron_expr(on_calendar: str) -> str:
    mapping = {
        "hourly": "0 * * * *",
        "daily": "0 3 * * *",
        "weekly": "0 3 * * 0",
    }
    return mapping.get(on_calendar, "0 3 * * *")


def generate(
    command: str,
    *,
    name: str = "sentinel-guard",
    on_calendar: str = "daily",
    user: str = "root",
    working_directory: str = "/opt/sentinel-guard",
) -> ScheduleUnit:
    """Build systemd + cron artifacts for a periodic *defensive* run of ``command``.

    ``command`` is the argument string after ``sentinel`` (e.g.
    ``"block --from-logs /var/log/auth.log"``). Red-team/sandbox subcommands are
    refused to keep scheduled runs defensive-only.
    """
    argv = shlex.split(command)
    for bad in _FORBIDDEN_SUBCOMMANDS:
        if bad in argv:
            raise ModeViolation(
                f"refused to schedule {bad!r}: active/attack validation is opt-in and "
                "sandbox-only, never scheduled"
            )

    exec_start = f"/usr/bin/env sentinel {command}".rstrip()
    service_text = "\n".join(
        [
            "[Unit]",
            f"Description=Sentinel-Guard periodic defensive run ({command})",
            "After=network-online.target",
            "Wants=network-online.target",
            "",
            "[Service]",
            "Type=oneshot",
            f"User={user}",
            f"WorkingDirectory={working_directory}",
            f"ExecStart={exec_start}",
            # hardening for the unit itself
            "NoNewPrivileges=true",
            "ProtectSystem=strict",
            "ProtectHome=read-only",
            f"ReadWritePaths={working_directory}/state",
            "PrivateTmp=true",
            "",
            "[Install]",
            "WantedBy=multi-user.target",
            "",
        ]
    )
    timer_text = "\n".join(
        [
            "[Unit]",
            f"Description=Run {name}.service on a schedule",
            "",
            "[Timer]",
            f"OnCalendar={on_calendar}",
            "Persistent=true",
            "RandomizedDelaySec=300",
            f"Unit={name}.service",
            "",
            "[Install]",
            "WantedBy=timers.target",
            "",
        ]
    )
    cron_line = (
        f"{_cron_expr(on_calendar)} {user} cd {working_directory} && "
        f"/usr/bin/env sentinel {command}"
    )
    return ScheduleUnit(
        name=name,
        command=command,
        on_calendar=on_calendar,
        service_text=service_text,
        timer_text=timer_text,
        cron_line=cron_line,
    )
