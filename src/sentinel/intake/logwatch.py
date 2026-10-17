"""Minimal, dependency-free log analysis for brute-force / probing sources.

Pure functions over text so they are trivially testable and never touch the
network. The caller decides what to do with the detected IPs (the Block engine
routes them through the guard).
"""

from __future__ import annotations

import ipaddress
import re
from collections import Counter
from dataclasses import dataclass

# sshd failed auth lines, e.g.:
#   "Failed password for invalid user root from 203.0.113.9 port 51234 ssh2"
#   "Failed password for deploy from 198.51.100.4 port 2222 ssh2"
_SSHD_FAIL = re.compile(r"Failed password for (?:invalid user )?\S+ from (\S+) port")
# generic "from <ip>" auth failures
_AUTH_FAIL = re.compile(r"authentication failure.*rhost=(\S+)")


@dataclass(frozen=True)
class LogSignal:
    ip: str
    count: int
    reason: str


def _valid_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def detect_bruteforce_ips(lines, threshold: int = 5) -> list[LogSignal]:
    """Return IPs whose failed-auth count meets ``threshold``.

    ``lines`` is any iterable of log lines (strings).
    """
    counts: Counter[str] = Counter()
    for line in lines:
        for pat in (_SSHD_FAIL, _AUTH_FAIL):
            m = pat.search(line)
            if m:
                ip = m.group(1)
                if _valid_ip(ip):
                    counts[ip] += 1
                break
    return [
        LogSignal(ip=ip, count=c, reason="ssh/pam auth failures")
        for ip, c in sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))
        if c >= threshold
    ]
