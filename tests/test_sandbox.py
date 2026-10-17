"""Sandbox replay must be sandbox-only, non-production, and never escalate.

These mirror the fail-closed style of test_guard.py: the sandbox's attack-style
validation routes through the same REDTEAM_ATTACK gate, so production targets,
a missing sandbox environment, and a disabled toggle are all refused.
"""

from __future__ import annotations

import pytest

from sentinel.core.errors import ModeViolation, ScopeViolation
from sentinel.guards import ScopeGuard
from sentinel.sandbox import SandboxReplay


def _guard(make_env, **toggles):
    return ScopeGuard.from_settings(make_env(**toggles).settings)


def test_validate_refused_without_redteam_toggle(make_env):
    guard = _guard(make_env, enable_sandbox_redteam=False)
    sb = SandboxReplay(guard, replica="10.0.0.5")
    with pytest.raises(ModeViolation):
        sb.validate("nuclei", ["docker", "run", "--rm", "nuclei", "-u", "http://web"])


def test_validate_refused_on_production_replica(make_env):
    # Even with the toggle on, a production replica id is hard-refused.
    guard = _guard(make_env, enable_sandbox_redteam=True)
    sb = SandboxReplay(guard, replica="web01.test.internal")
    with pytest.raises(ModeViolation):
        sb.validate("probe", ["docker", "run", "--rm", "busybox", "true"])


def test_validate_refused_out_of_scope(make_env):
    guard = _guard(make_env, enable_sandbox_redteam=True)
    sb = SandboxReplay(guard, replica="8.8.8.8")
    with pytest.raises(ScopeViolation):
        sb.validate("probe", ["docker", "run", "--rm", "busybox", "true"])


def test_validate_dry_run_returns_plan_only(make_env):
    guard = _guard(make_env, enable_sandbox_redteam=True)
    sb = SandboxReplay(guard, replica="10.0.0.5")
    res = sb.validate("nuclei", ["docker", "run", "--rm", "nuclei"])
    assert res.dry_run is True
    assert res.returncode is None  # nothing executed


def test_privileged_is_refused_in_validation(make_env):
    guard = _guard(make_env, enable_sandbox_redteam=True)
    sb = SandboxReplay(guard, replica="10.0.0.5")
    with pytest.raises(ModeViolation):
        sb.validate("bad", ["docker", "run", "--privileged", "busybox"])


def test_network_is_internal_and_dedicated(make_env):
    guard = _guard(make_env, enable_sandbox_redteam=True)
    sb = SandboxReplay(guard, replica="10.0.0.5")
    create = sb.up_commands()[0]
    assert create[:3] == ["docker", "network", "create"]
    assert "--internal" in create
    assert sb.network.startswith("sentinel_sbx_")


def test_replay_tears_down_even_if_validation_runs(make_env):
    guard = _guard(make_env, enable_sandbox_redteam=True)
    sb = SandboxReplay(guard, replica="10.0.0.5")
    plan = sb.replay([("probe", ["docker", "run", "--rm", "busybox", "true"])])
    assert plan.dry_run is True
    assert any("network rm" in c for c in plan.down_commands)
    # the whole lifecycle is in the audit log
    events = [e["event"] for e in _audit_events(guard)]
    assert "sandbox.up.plan" in events
    assert "sandbox.validate.plan" in events
    assert "sandbox.down.plan" in events


def test_validate_executes_when_not_dry_run(make_env):
    env = make_env(enable_sandbox_redteam=True)
    env.settings.dry_run = False
    guard = ScopeGuard.from_settings(env.settings)
    calls = []

    def fake_runner(args):
        calls.append(args)
        return 0, "finding confirmed"

    sb = SandboxReplay(guard, replica="10.0.0.5", runner=fake_runner)
    res = sb.validate("nuclei", ["docker", "run", "--rm", "nuclei"])
    assert res.dry_run is False
    assert res.breached is True  # rc == 0
    assert calls == [["docker", "run", "--rm", "nuclei"]]


def _audit_events(guard):
    import json
    from pathlib import Path

    path = Path(guard.settings.paths.audit_file)
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
