"""AnthropicBackend wires REAL response tokens into the usage Governor, and the
budget governor selects the model and stops calls when exhausted."""

from __future__ import annotations

import pytest

from sentinel.core.config import UsageConfig
from sentinel.patch.llm import AnthropicBackend
from sentinel.patch.model import Finding
from sentinel.usage.governor import Governor
from sentinel.usage.ledger import UsageLedger


class _Usage:
    input_tokens = 1200
    output_tokens = 800


class _Block:
    def __init__(self, text):
        self.text = text


class _Msg:
    content = [_Block("PermitRootLogin no\n")]
    usage = _Usage()


class _Msgs:
    last = None

    def create(self, **kw):
        _Msgs.last = kw
        return _Msg()


class _FakeClient:
    def __init__(self):
        self.messages = _Msgs()


def _finding():
    return Finding(
        id="F1", target="10.0.0.5", service="sshd", title="harden sshd",
        path="/etc/ssh/sshd_config", original="PermitRootLogin yes\n",
    )


def test_records_real_response_tokens_and_governor_picks_model(tmp_path, monkeypatch):
    led = UsageLedger(tmp_path / "usage.jsonl")
    gov = Governor(
        UsageConfig(provider="api", daily_token_budget=1_000_000,
                    model_tiers=["claude-opus-4-8", "claude-sonnet-4-8", "claude-haiku-4-8"]),
        led,
    )
    be = AnthropicBackend(governor=gov)
    monkeypatch.setattr(be, "_client", lambda: _FakeClient())

    cands = be.propose(_finding())
    assert cands and "PermitRootLogin no" in cands[0].hardened
    assert led.tokens_today() == 2000          # 1200 input + 800 output
    assert _Msgs.last["model"] == "claude-opus-4-8"  # budget fresh -> top tier


def test_governor_downgrades_model_when_budget_mostly_spent(tmp_path, monkeypatch):
    led = UsageLedger(tmp_path / "usage.jsonl")
    led.record(850_000)  # 85% -> throttled -> last tier
    gov = Governor(
        UsageConfig(provider="api", daily_token_budget=1_000_000,
                    model_tiers=["claude-opus-4-8", "claude-sonnet-4-8", "claude-haiku-4-8"]),
        led,
    )
    be = AnthropicBackend(governor=gov)
    monkeypatch.setattr(be, "_client", lambda: _FakeClient())
    be.propose(_finding())
    assert _Msgs.last["model"] == "claude-haiku-4-8"


def test_no_api_call_when_budget_exhausted(tmp_path, monkeypatch):
    led = UsageLedger(tmp_path / "usage.jsonl")
    led.record(1_000_000)  # at budget -> stopped
    gov = Governor(UsageConfig(provider="api", daily_token_budget=1_000_000), led)
    be = AnthropicBackend(governor=gov)

    def _boom():
        raise AssertionError("API must not be called when the governor has stopped")

    monkeypatch.setattr(be, "_client", _boom)
    cands = be.propose(_finding())            # falls back to offline rules, no API
    assert cands and "PermitRootLogin no" in cands[0].hardened
