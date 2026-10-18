"""Turn the daily token budget into a live run decision.

As today's spend climbs toward the budget, the governor steps the model down its
tiers, lowers run frequency, and finally stops — resuming automatically at the
next local-midnight rollover. For the CLI (subscription) provider there is no
token budget, so it never token-stops; only the frequency cap applies.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta

from ..core.config import UsageConfig
from .ledger import UsageLedger

LEVELS = ("normal", "downgraded", "throttled", "stopped")


@dataclass(frozen=True)
class GovernorState:
    provider: str
    tokens_today: int
    budget: int
    fraction: float
    level: str
    model: str
    runs_per_hour: int
    allow_run: bool
    resets_at: str

    def bar(self, width: int = 24) -> str:
        """A simple [####----] budget bar for the TUI/CLI."""
        filled = 0 if self.budget <= 0 else min(width, round(self.fraction * width))
        return "[" + "#" * filled + "-" * (width - filled) + "]"


class Governor:
    def __init__(self, config: UsageConfig, ledger: UsageLedger) -> None:
        self.config = config
        self.ledger = ledger

    @staticmethod
    def _next_midnight() -> datetime:
        now = datetime.now().astimezone()
        tomorrow = (now + timedelta(days=1)).replace(hour=0, minute=0, second=0, microsecond=0)
        return tomorrow

    def _model_for(self, fraction: float) -> str:
        tiers = self.config.model_tiers or ["claude-opus-4-8"]
        if fraction >= self.config.throttle_at:
            return tiers[-1]
        if fraction >= self.config.downgrade_at:
            return tiers[min(1, len(tiers) - 1)]
        return tiers[0]

    def _level_for(self, fraction: float) -> str:
        if fraction >= self.config.stop_at:
            return "stopped"
        if fraction >= self.config.throttle_at:
            return "throttled"
        if fraction >= self.config.downgrade_at:
            return "downgraded"
        return "normal"

    def state(self) -> GovernorState:
        tokens = self.ledger.tokens_today()
        budget = self.config.daily_token_budget

        if self.config.provider == "cli" or budget <= 0:
            # subscription / unmetered: never token-stop; frequency cap still applies
            fraction = 0.0
            level = "normal"
            model = (self.config.model_tiers or ["claude-opus-4-8"])[0]
            runs = self.config.base_runs_per_hour
            allow = True
        else:
            fraction = min(1.0, tokens / budget)
            level = self._level_for(fraction)
            model = self._model_for(fraction)
            if level == "stopped":
                runs, allow = 0, False
            elif level == "throttled":
                runs, allow = max(1, self.config.base_runs_per_hour // 4), True
            elif level == "downgraded":
                runs, allow = max(1, self.config.base_runs_per_hour // 2), True
            else:
                runs, allow = self.config.base_runs_per_hour, True

        return GovernorState(
            provider=self.config.provider,
            tokens_today=tokens,
            budget=budget,
            fraction=round(fraction, 4),
            level=level,
            model=model,
            runs_per_hour=runs,
            allow_run=allow,
            resets_at=self._next_midnight().isoformat(),
        )

    def record(self, tokens: int, model: str = "", op: str = "") -> GovernorState:
        self.ledger.record(tokens, model=model, op=op)
        return self.state()
