"""Append-only, hash-chained audit log.

Every authorization decision (allow/deny) and every active operation is recorded.
Each entry embeds the hash of the previous entry, so removing or altering any
line breaks the chain and is detectable by :meth:`AuditLog.verify_chain`.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from .signing import canonical_bytes, sha256_hex

GENESIS = "0" * 64


class AuditLog:
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._last_hash, self._seq = self._tail_state()

    def _tail_state(self) -> tuple[str, int]:
        if not self.path.exists():
            return GENESIS, 0
        last_hash, seq = GENESIS, 0
        with self.path.open("r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                entry = json.loads(line)
                last_hash = entry["hash"]
                seq = entry["seq"]
        return last_hash, seq

    @staticmethod
    def _now() -> str:
        return datetime.now(timezone.utc).isoformat()

    def append(self, event: str, data: Optional[dict[str, Any]] = None) -> dict:
        """Append an entry and return it. The entry hash chains to the previous one."""
        seq = self._seq + 1
        core = {
            "seq": seq,
            "ts": self._now(),
            "event": event,
            "data": data or {},
            "prev": self._last_hash,
        }
        entry_hash = sha256_hex(canonical_bytes(core))
        entry = {**core, "hash": entry_hash}
        with self.path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry, ensure_ascii=False, sort_keys=True) + "\n")
        try:
            self.path.chmod(0o640)
        except OSError:
            pass
        self._last_hash, self._seq = entry_hash, seq
        return entry

    def verify_chain(self) -> bool:
        """Return True iff the on-disk chain is intact. Raises nothing."""
        if not self.path.exists():
            return True
        prev = GENESIS
        expected_seq = 1
        with self.path.open("r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError:
                    return False
                if entry.get("prev") != prev or entry.get("seq") != expected_seq:
                    return False
                core = {k: entry[k] for k in ("seq", "ts", "event", "data", "prev")}
                if sha256_hex(canonical_bytes(core)) != entry.get("hash"):
                    return False
                prev = entry["hash"]
                expected_seq += 1
        return True
