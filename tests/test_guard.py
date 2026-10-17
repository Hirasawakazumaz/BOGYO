"""The guard must fail closed. These tests are the safety contract."""

from __future__ import annotations

import pytest

from sentinel.core import killswitch
from sentinel.core.actions import ActionClass
from sentinel.core.errors import LimitExceeded, ModeViolation, ScopeViolation
from sentinel.guards import ScopeGuard


def test_in_scope_passive_read_allowed(make_env):
    guard = ScopeGuard.from_settings(make_env().settings)
    d = guard.authorize(ActionClass.PASSIVE_READ, target="203.0.113.10")
    assert d.dry_run is True


def test_out_of_scope_target_refused(make_env):
    guard = ScopeGuard.from_settings(make_env(enable_active_scan=True).settings)
    with pytest.raises(ScopeViolation):
        guard.authorize(ActionClass.ACTIVE_SCAN, target="8.8.8.8")


def test_active_scan_requires_toggle(make_env):
    guard = ScopeGuard.from_settings(make_env(enable_active_scan=False).settings)
    with pytest.raises(ModeViolation):
        guard.authorize(ActionClass.ACTIVE_SCAN, target="203.0.113.10")


def test_active_scan_allowed_when_enabled_and_in_scope(make_env):
    guard = ScopeGuard.from_settings(make_env(enable_active_scan=True).settings)
    d = guard.authorize(ActionClass.ACTIVE_SCAN, target="203.0.113.10")
    assert d.action is ActionClass.ACTIVE_SCAN


def test_redteam_on_production_hard_refused(make_env):
    # Even with the toggle on and environment=sandbox, production is refused.
    guard = ScopeGuard.from_settings(make_env(enable_sandbox_redteam=True).settings)
    with pytest.raises(ModeViolation):
        guard.authorize(
            ActionClass.REDTEAM_ATTACK, target="web01.test.internal", environment="sandbox"
        )


def test_redteam_requires_sandbox_environment(make_env):
    guard = ScopeGuard.from_settings(make_env(enable_sandbox_redteam=True).settings)
    # In-scope non-production host but no sandbox environment -> refused.
    with pytest.raises(ModeViolation):
        guard.authorize(ActionClass.REDTEAM_ATTACK, target="10.0.0.5", environment=None)


def test_redteam_requires_toggle(make_env):
    guard = ScopeGuard.from_settings(make_env(enable_sandbox_redteam=False).settings)
    with pytest.raises(ModeViolation):
        guard.authorize(ActionClass.REDTEAM_ATTACK, target="10.0.0.5", environment="sandbox")


def test_redteam_allowed_sandbox_nonprod_with_toggle(make_env):
    guard = ScopeGuard.from_settings(make_env(enable_sandbox_redteam=True).settings)
    d = guard.authorize(ActionClass.REDTEAM_ATTACK, target="10.0.0.5", environment="sandbox")
    assert d.environment == "sandbox"


def test_block_requires_toggle(make_env):
    guard = ScopeGuard.from_settings(make_env(enable_blocking=False).settings)
    with pytest.raises(ModeViolation):
        guard.authorize(ActionClass.BLOCK, target="198.51.100.9")


def test_block_allowed_even_out_of_scope_when_enabled(make_env):
    # Defensive blocking of an arbitrary inbound attacker IP is permitted.
    guard = ScopeGuard.from_settings(make_env(enable_blocking=True).settings)
    d = guard.authorize(ActionClass.BLOCK, target="198.51.100.9")
    assert d.action is ActionClass.BLOCK


def test_patch_apply_requires_approval(make_env):
    guard = ScopeGuard.from_settings(make_env(enable_patch_apply=True).settings)
    with pytest.raises(ModeViolation):
        guard.authorize(ActionClass.PATCH_APPLY, target="10.0.0.5", approved=False)
    d = guard.authorize(ActionClass.PATCH_APPLY, target="10.0.0.5", approved=True)
    assert d.action is ActionClass.PATCH_APPLY


def test_killswitch_blocks_construction(make_env):
    env = make_env(enable_active_scan=True)
    killswitch.engage(env.settings.paths.killswitch_file, reason="test")
    from sentinel.core.errors import KillSwitchEngaged

    with pytest.raises(KillSwitchEngaged):
        ScopeGuard.from_settings(env.settings)


def test_max_targets_limit(make_env):
    env = make_env(enable_active_scan=True)
    env.settings.limits.max_targets_per_run = 2
    guard = ScopeGuard.from_settings(env.settings)
    guard.authorize(ActionClass.ACTIVE_SCAN, target="10.0.0.1")
    guard.authorize(ActionClass.ACTIVE_SCAN, target="10.0.0.2")
    with pytest.raises(LimitExceeded):
        guard.authorize(ActionClass.ACTIVE_SCAN, target="10.0.0.3")
