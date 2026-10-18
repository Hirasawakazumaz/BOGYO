"""Append-only token-usage ledger (one JSON object per line).

Each entry: {ts, date, tokens, model, op}. ``tokens_on`` sums a given local date,
which is how the governor measures "today's" spend against the daily budget.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional


class UsageLedger:
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    @staticmethod
    def _now() -> datetime:
        return datetime.now(timezone.utc).astimezone()  # local tz

    def record(self, tokens: int, model: str = "", op: str = "") -> dict:
        now = self._now()
        entry = {
            "ts": now.isoformat(),
            "date": now.strftime("%Y-%m-%d"),
            "tokens": int(tokens),
            "model": model,
            "op": op,
        }
        with self.path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry, ensure_ascii=False) + "\n")
        return entry

    def _iter(self):
        if not self.path.exists():
            return
        for line in self.path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError:
                continue

    def tokens_on(self, date_str: Optional[str] = None) -> int:
        date_str = date_str or self._now().strftime("%Y-%m-%d")
        return sum(int(e.get("tokens", 0)) for e in self._iter() if e.get("date") == date_str)

    def tokens_today(self) -> int:
        return self.tokens_on()

    def by_model_today(self) -> dict[str, int]:
        today = self._now().strftime("%Y-%m-%d")
        out: dict[str, int] = {}
        for e in self._iter():
            if e.get("date") == today:
                out[e.get("model", "?")] = out.get(e.get("model", "?"), 0) + int(e.get("tokens", 0))
        return out
