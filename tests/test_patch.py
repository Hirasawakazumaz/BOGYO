"""Patch proposal, sandbox conflict-eval loop, and guarded host apply."""

from __future__ import annotations

import pytest

from sentinel.core.errors import ModeViolation, ScopeViolation
from sentinel.guards import ScopeGuard
from sentinel.patch import (
    ConflictEvaluator,
    Finding,
    PatchLoop,
    PatchProposer,
    RuleBackend,
    apply_to_host,
)

SSHD = "PermitRootLogin yes\nPasswordAuthentication yes\nX11Forwarding yes\n"


def _guard(make_env, **kw):
    return ScopeGuard.from_settings(make_env(**kw).settings)


def _finding() -> Finding:
    return Finding(
        id="F-1",
        target="10.0.0.5",
        service="sshd",
        title="weak sshd config",
        path="/etc/ssh/sshd_config",
        original=SSHD,
    )


def test_offline_proposer_is_deterministic(make_env):
    guard = _guard(make_env)
    cands = PatchProposer(guard, RuleBackend()).propose(_finding())
    assert len(cands) == 1
    c = cands[0]
    assert "PermitRootLogin no" in c.hardened
    assert "PasswordAuthentication no" in c.hardened
    # reproducible
    again = PatchProposer(guard, RuleBackend()).propose(_finding())[0]
    assert again.hardened == c.hardened


def test_candidate_produces_unified_diff(make_env):
    guard = _guard(make_env)
    c = PatchProposer(guard, RuleBackend()).propose(_finding())[0]
    diff = c.unified_diff()
    assert "sshd_config" in diff  # path present in headers
    assert "-PermitRootLogin yes" in diff
    assert "+PermitRootLogin no" in diff


def test_loop_accepts_when_checks_pass(make_env):
    env = make_env(enable_sandbox_redteam=True)
    env.settings.dry_run = False
    guard = ScopeGuard.from_settings(env.settings)
    proposer = PatchProposer(guard, RuleBackend())
    evaluator = ConflictEvaluator(guard, runner=lambda args: (0, "ok"))
    loop = PatchLoop(proposer, evaluator)
    result = loop.run(_finding(), checks=[("startup:restart", ["docker", "restart", "sshd"])])
    assert result.accepted is True
    assert result.rounds == 1


def test_loop_refines_on_conflict_then_accepts(make_env):
    env = make_env()
    env.settings.dry_run = False
    guard = ScopeGuard.from_settings(env.settings)
    proposer = PatchProposer(guard, RuleBackend())

    # First evaluation fails (rc!=0), subsequent ones pass -> forces a refine round.
    seq = iter([1, 0, 0, 0])

    def runner(args):
        return next(seq, 0), "out"

    evaluator = ConflictEvaluator(guard, runner=runner)
    loop = PatchLoop(proposer, evaluator)
    result = loop.run(_finding(), checks=[("startup:restart", ["true"])], max_rounds=3)
    assert result.accepted is True
    assert result.rounds == 2  # needed one refine


def test_apply_to_host_requires_toggle_and_approval(make_env):
    env = make_env(enable_patch_apply=False)
    guard = ScopeGuard.from_settings(env.settings)
    c = PatchProposer(guard, RuleBackend()).propose(_finding())[0]

    # toggle off -> refused (even if approved)
    with pytest.raises(ModeViolation):
        apply_to_host(guard, c, host="10.0.0.5", approved=True)

    # toggle on but not approved -> still refused
    env.settings.toggles.enable_patch_apply = True
    with pytest.raises(ModeViolation):
        apply_to_host(guard, c, host="10.0.0.5", approved=False)


def test_apply_to_host_out_of_scope_refused(make_env):
    g = _guard(make_env, enable_patch_apply=True)
    c = PatchProposer(g, RuleBackend()).propose(_finding())[0]
    with pytest.raises(ScopeViolation):
        apply_to_host(g, c, host="8.8.8.8", approved=True)


def test_apply_to_host_dry_run_writes_nothing(make_env, tmp_path):
    g = _guard(make_env, enable_patch_apply=True)  # dry_run defaults True
    target_file = tmp_path / "sshd_config"
    target_file.write_text(SSHD, encoding="utf-8")
    finding = Finding(id="F-1", target="10.0.0.5", service="sshd", title="x",
                      path=str(target_file), original=SSHD)
    c = PatchProposer(g, RuleBackend()).propose(finding)[0]
    res = apply_to_host(g, c, host="10.0.0.5", approved=True)
    assert res.dry_run is True
    assert res.applied is False
    assert target_file.read_text(encoding="utf-8") == SSHD  # untouched
    assert "PermitRootLogin no" in res.diff


def test_privileged_check_refused(make_env):
    guard = _guard(make_env)
    c = PatchProposer(guard, RuleBackend()).propose(_finding())[0]
    evaluator = ConflictEvaluator(guard)
    with pytest.raises(ModeViolation):
        evaluator.evaluate(c, checks=[("startup", ["docker", "run", "--privileged", "x"])])
