"""Audit hash-chain integrity, log intake, and defensive blocking (dry-run + applied)."""

from __future__ import annotations

from sentinel.block import FirewallBlocker
from sentinel.core.audit import AuditLog
from sentinel.guards import ScopeGuard
from sentinel.intake import detect_bruteforce_ips


def test_audit_chain_detects_tampering(tmp_path):
    log = AuditLog(tmp_path / "audit.jsonl")
    log.append("a", {"x": 1})
    log.append("b", {"y": 2})
    assert log.verify_chain() is True
    # Tamper: alter a hashed field of the first entry without updating its hash.
    p = tmp_path / "audit.jsonl"
    lines = p.read_text(encoding="utf-8").splitlines()
    assert '"event": "a"' in lines[0]
    lines[0] = lines[0].replace('"event": "a"', '"event": "zzz"')
    p.write_text("\n".join(lines) + "\n", encoding="utf-8")
    assert log.verify_chain() is False


def test_detect_bruteforce_ips():
    lines = [
        "Jan 1 00:00:01 h sshd[1]: Failed password for invalid user root from 203.0.113.9 port 1 ssh2",
        "Jan 1 00:00:02 h sshd[1]: Failed password for root from 203.0.113.9 port 2 ssh2",
        "Jan 1 00:00:03 h sshd[1]: Failed password for root from 203.0.113.9 port 3 ssh2",
        "Jan 1 00:00:04 h sshd[1]: Failed password for root from 198.51.100.1 port 4 ssh2",
        "Jan 1 00:00:05 h sshd[1]: Accepted password for deploy from 10.0.0.2 port 5 ssh2",
    ]
    sig = detect_bruteforce_ips(lines, threshold=3)
    assert len(sig) == 1 and sig[0].ip == "203.0.113.9" and sig[0].count == 3


def test_block_dry_run_builds_command(make_env):
    guard = ScopeGuard.from_settings(make_env(enable_blocking=True, dry_run=True).settings)
    blocker = FirewallBlocker(guard)
    res = blocker.block_ip("198.51.100.9", ttl_seconds=600)
    assert res.dry_run is True and res.executed is False
    assert "add element inet sentinel_guard blocked_v4" in res.command
    assert "198.51.100.9 timeout 600s" in res.command


def test_block_applied_uses_runner(make_env):
    calls = []

    def fake_runner(args):
        calls.append(args)
        return 0

    guard = ScopeGuard.from_settings(make_env(enable_blocking=True, dry_run=False).settings)
    blocker = FirewallBlocker(guard, runner=fake_runner)
    # monkeypatch shutil.which via blocker module not needed if we trust runner;
    # but block_ip checks for nft presence. Provide it by faking which.
    import sentinel.block.blocker as b

    orig = b.shutil.which
    b.shutil.which = lambda _x: "/usr/sbin/nft"
    try:
        res = blocker.block_ip("2001:db8::1", ttl_seconds=120)
    finally:
        b.shutil.which = orig
    assert res.executed is True and res.dry_run is False
    assert calls and calls[0][0] == "nft"
    assert "blocked_v6" in res.command
