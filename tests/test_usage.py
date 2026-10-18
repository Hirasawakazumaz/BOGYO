"""Usage governor: budget-driven model downgrade, throttling, stop, and resume."""

from __future__ import annotations

from sentinel.core.config import UsageConfig
from sentinel.usage.governor import Governor
from sentinel.usage.ledger import UsageLedger


def _gov(tmp_path, **cfg):
    led = UsageLedger(tmp_path / "usage.jsonl")
    return Governor(UsageConfig(**cfg), led), led


def test_normal_when_under_budget(tmp_path):
    gov, led = _gov(tmp_path, daily_token_budget=1000, model_tiers=["A", "B", "C"])
    led.record(100)
    st = gov.state()
    assert st.level == "normal" and st.model == "A" and st.allow_run is True


def test_downgrade_then_throttle_then_stop(tmp_path):
    gov, led = _gov(
        tmp_path, daily_token_budget=1000, model_tiers=["A", "B", "C"],
        downgrade_at=0.6, throttle_at=0.8, stop_at=1.0, base_runs_per_hour=12,
    )
    led.record(650)  # 65% -> downgraded
    st = gov.state()
    assert st.level == "downgraded" and st.model == "B" and st.runs_per_hour == 6
    led.record(200)  # 85% -> throttled
    st = gov.state()
    assert st.level == "throttled" and st.model == "C" and st.runs_per_hour == 3
    led.record(200)  # 105% -> stopped
    st = gov.state()
    assert st.level == "stopped" and st.allow_run is False and st.runs_per_hour == 0


def test_cli_provider_never_token_stops(tmp_path):
    gov, led = _gov(tmp_path, provider="cli", daily_token_budget=10)
    led.record(99999)
    st = gov.state()
    assert st.allow_run is True and st.level == "normal"


def test_ledger_sums_today(tmp_path):
    led = UsageLedger(tmp_path / "usage.jsonl")
    led.record(10, model="A")
    led.record(5, model="B")
    assert led.tokens_today() == 15
    assert led.by_model_today() == {"A": 10, "B": 5}
