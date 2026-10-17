"""Threat intake: turn local logs and threat-intel feeds into attacker IPs."""

from .logwatch import LogSignal, detect_bruteforce_ips

__all__ = ["LogSignal", "detect_bruteforce_ips"]
