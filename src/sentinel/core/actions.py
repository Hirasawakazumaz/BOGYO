"""Classification of every operation the system can perform.

The guard applies different rules per class. This enum is the vocabulary the
whole codebase uses when asking the guard for authorization.
"""

from __future__ import annotations

from enum import Enum


class ActionClass(str, Enum):
    #: Reading local logs, config, public CVE data. No packets sent to a target.
    PASSIVE_READ = "passive_read"
    #: Active probing of an in-scope host (nmap/nuclei/ZAP). Touches the target.
    ACTIVE_SCAN = "active_scan"
    #: Exploit/attack validation. SANDBOX REPLICAS ONLY — never production.
    REDTEAM_ATTACK = "redteam_attack"
    #: Adding/removing a firewall block for an attacking source IP (defensive).
    BLOCK = "block"
    #: Generating a patch/hardening candidate (no application).
    PATCH_PROPOSE = "patch_propose"
    #: Applying a patch to a real host. Requires explicit human approval.
    PATCH_APPLY = "patch_apply"


#: Action classes that send traffic to / act on a target host.
ACTIVE_CLASSES = frozenset(
    {ActionClass.ACTIVE_SCAN, ActionClass.REDTEAM_ATTACK, ActionClass.PATCH_APPLY}
)

#: Action classes that are only ever allowed against an isolated sandbox replica.
SANDBOX_ONLY_CLASSES = frozenset({ActionClass.REDTEAM_ATTACK})
