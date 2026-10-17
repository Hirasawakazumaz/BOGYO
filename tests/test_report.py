"""Reports are built purely from the audit log and reflect tallies + integrity."""

from __future__ import annotations

from sentinel.core.actions import ActionClass
from sentinel.guards import ScopeGuard
from sentinel.report import ReportBuilder
from sentinel.sandbox import SandboxReplay


def test_report_tallies_allow_deny_and_breaches(make_env, tmp_path):
    env = make_env(enable_sandbox_redteam=True)
    env.settings.dry_run = False
    guard = ScopeGuard.from_settings(env.settings)

    # one confirmed breach in the sandbox
    sb = SandboxReplay(guard, replica="10.0.0.5", runner=lambda a: (0, "hit"))
    sb.validate("nuclei", ["docker", "run", "--rm", "nuclei"])

    # one denied action (out of scope)
    try:
        guard.authorize(ActionClass.REDTEAM_ATTACK, target="8.8.8.8", environment="sandbox")
    except Exception:
        pass

    report = ReportBuilder(guard.settings.paths.audit_file).build()
    assert report.chain_intact is True
    assert report.allowed >= 1
    assert report.denied >= 1
    assert report.breaches == 1
    md = report.to_markdown()
    assert "Breach tally" in md
    assert "findings confirmed (breached in sandbox): **1**" in md


def test_report_writes_files(make_env, tmp_path):
    guard = ScopeGuard.from_settings(make_env().settings)
    guard.authorize(ActionClass.PASSIVE_READ, target="10.0.0.5")
    md, js = tmp_path / "r.md", tmp_path / "r.json"
    ReportBuilder(guard.settings.paths.audit_file).write(md, js)
    assert md.exists() and js.exists()
    assert "Sentinel-Guard run report" in md.read_text(encoding="utf-8")


def test_report_detects_tampered_chain(make_env, tmp_path):
    guard = ScopeGuard.from_settings(make_env().settings)
    guard.authorize(ActionClass.PASSIVE_READ, target="10.0.0.5")
    # corrupt the audit log
    p = guard.settings.paths.audit_file
    from pathlib import Path

    lines = Path(p).read_text(encoding="utf-8").splitlines()
    lines.append('{"seq": 999, "ts": "x", "event": "forged", "data": {}, "prev": "0", "hash": "bad"}')
    Path(p).write_text("\n".join(lines) + "\n", encoding="utf-8")

    report = ReportBuilder(p).build()
    assert report.chain_intact is False
    assert "TAMPERED" in report.to_markdown()
