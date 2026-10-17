"""Defensive firewall blocking (drop inbound from attacker IPs). Never retaliates."""

from .blocker import BlockResult, FirewallBlocker

__all__ = ["FirewallBlocker", "BlockResult"]
