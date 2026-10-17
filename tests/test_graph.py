"""The orchestrator must guard every node and stay importable/runnable offline."""

from __future__ import annotations

import json
from pathlib import Path

from sentinel.graph import PipelineConfig, SentinelPipeline
from sentinel.guards import ScopeGuard
from sentinel.patch import Finding, RuleBackend

AUTH_LOG = [
    "Failed password for root from 203.0.113.9 port 51234 ssh2",
] * 6


def _audit_events(guard):
    path = Path(guard.settings.paths.audit_file)
    return [json.loads(l) for l in path.read_text(encoding="utf-8").splitlines() if l.strip()]


def _finding():
    return Finding(
        id="F-1", target="10.0.0.5", service="sshd", title="weak sshd",
        path="/etc/ssh/sshd_config", original="PermitRootLogin yes\n",
    )


def test_import_graph_without_agent_extra():
    # Importing the package must not require langgraph/anthropic.
    import importlib

    mod = importlib.import_module("sentinel.graph")
    assert hasattr(mod, "SentinelPipeline")


def test_pipeline_runs_end_to_end_in_dry_run(make_env, tmp_path):
    guard = ScopeGuard.from_settings(
        make_env(enable_active_scan=True, enable_sandbox_redteam=True).settings
    )
    cfg = PipelineConfig(
        target="10.0.0.5",
        log_lines=AUTH_LOG,
        replica="10.0.0.5",
        validations=[("nuclei", ["docker", "run", "--rm", "--network", "sentinel_sbx_10_0_0_5", "nuclei"])],
        findings=[_finding()],
        patch_backend=RuleBackend(),
        report_md=str(tmp_path / "report.md"),
        report_json=str(tmp_path / "report.json"),
    )
    state = SentinelPipeline(guard).run(cfg)

    assert state.attacker_ips == ["203.0.113.9"]
    assert state.scan_plans and state.scan_plans[0].dry_run is True
    assert state.sandbox_plan is not None
    assert state.candidates and "PermitRootLogin no" in state.candidates[0].hardened
    assert state.evaluations
    assert state.report is not None
    assert (tmp_path / "report.md").exists()

    # every node's work is in the audit log
    events = {e["event"] for e in _audit_events(guard)}
    assert {"graph.start", "graph.intake", "graph.report", "graph.done"} <= events


def test_pipeline_skips_disabled_capabilities_but_completes(make_env, tmp_path):
    # All active toggles OFF: scan & sandbox are refused by the guard and skipped,
    # yet the pipeline still finishes and writes a report (fail-closed per node).
    guard = ScopeGuard.from_settings(make_env().settings)
    cfg = PipelineConfig(
        target="10.0.0.5",
        log_lines=AUTH_LOG,
        replica="10.0.0.5",
        validations=[("probe", ["docker", "run", "--rm", "busybox", "true"])],
        findings=[_finding()],
        patch_backend=RuleBackend(),
        report_md=str(tmp_path / "r.md"),
    )
    state = SentinelPipeline(guard).run(cfg)

    assert any(s.startswith("scan:") for s in state.skipped)
    assert any(s.startswith("sandbox:") for s in state.skipped)
    assert not state.scan_plans
    assert state.report is not None  # pipeline still completed
    # the guard was still asked (and denied) for the active actions
    events = [e["event"] for e in _audit_events(guard)]
    assert "authorize.deny" in events


def test_build_langgraph_errors_clearly_without_extra(make_env):
    import pytest

    guard = ScopeGuard.from_settings(make_env().settings)
    try:
        import langgraph  # noqa: F401
    except ImportError:
        from sentinel.graph import build_langgraph

        with pytest.raises(RuntimeError, match="langgraph is not installed"):
            build_langgraph(guard)
