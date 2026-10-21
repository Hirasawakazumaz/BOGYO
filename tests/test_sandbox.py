"""Sandbox replay must be sandbox-only, non-production, isolated, and un-escapable.

These mirror the fail-closed style of test_guard.py: the sandbox's attack-style
validation routes through the same REDTEAM_ATTACK gate, and every compose
isolation hole / command escape hatch is refused by structural analysis.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from sentinel.core.errors import ModeViolation, ScopeViolation
from sentinel.guards import ScopeGuard
from sentinel.sandbox import SandboxReplay


def _guard(make_env, **toggles):
    return ScopeGuard.from_settings(make_env(**toggles).settings)


def _run(sb, *args):
    """A sandbox-bound docker-run validation command (satisfies the F3 binding)."""
    return ["docker", "run", "--rm", "--network", sb.network, *args]


def _audit_events(guard):
    path = Path(guard.settings.paths.audit_file)
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


# --------------------------------------------------------------------------- #
# the REDTEAM gate (unchanged contract)
# --------------------------------------------------------------------------- #
def test_validate_refused_without_redteam_toggle(make_env):
    guard = _guard(make_env, enable_sandbox_redteam=False)
    sb = SandboxReplay(guard, replica="10.0.0.5")
    with pytest.raises(ModeViolation):
        sb.validate("nuclei", _run(sb, "nuclei", "-u", "http://web"))


def test_validate_refused_on_production_replica(make_env):
    guard = _guard(make_env, enable_sandbox_redteam=True)
    sb = SandboxReplay(guard, replica="web01.test.internal")
    with pytest.raises(ModeViolation):
        sb.validate("probe", _run(sb, "busybox", "true"))


def test_validate_refused_out_of_scope(make_env):
    guard = _guard(make_env, enable_sandbox_redteam=True)
    sb = SandboxReplay(guard, replica="8.8.8.8")
    with pytest.raises(ScopeViolation):
        sb.validate("probe", _run(sb, "busybox", "true"))


def test_validate_dry_run_returns_plan_only(make_env):
    guard = _guard(make_env, enable_sandbox_redteam=True)
    sb = SandboxReplay(guard, replica="10.0.0.5")
    res = sb.validate("nuclei", _run(sb, "nuclei"))
    assert res.dry_run is True
    assert res.returncode is None  # nothing executed


def test_validate_executes_when_not_dry_run(make_env):
    env = make_env(enable_sandbox_redteam=True)
    env.settings.dry_run = False
    guard = ScopeGuard.from_settings(env.settings)
    calls = []

    def fake_runner(args):
        calls.append(args)
        return 0, "finding confirmed"

    sb = SandboxReplay(guard, replica="10.0.0.5", runner=fake_runner)
    cmd = _run(sb, "nuclei")
    res = sb.validate("nuclei", cmd)
    assert res.dry_run is False
    assert res.breached is True  # rc == 0
    assert calls == [cmd]


# --------------------------------------------------------------------------- #
# command escalation (string-level backstop; primary defense is compose structure)
# --------------------------------------------------------------------------- #
def test_privileged_is_refused_in_validation(make_env):
    guard = _guard(make_env, enable_sandbox_redteam=True)
    sb = SandboxReplay(guard, replica="10.0.0.5")
    with pytest.raises(ModeViolation):
        sb.validate("bad", ["docker", "run", "--network", sb.network, "--privileged", "busybox"])


@pytest.mark.parametrize(
    "extra",
    [
        ["--net=host", "busybox"],
        ["--network", "host", "busybox"],
        ["--pid=host", "busybox"],
        ["--cap-add", "SYS_ADMIN", "busybox"],
        ["-v", "/var/run/docker.sock:/var/run/docker.sock", "busybox"],
        ["--security-opt", "seccomp=unconfined", "busybox"],
    ],
)
def test_command_escape_hatches_refused(make_env, extra):
    guard = _guard(make_env, enable_sandbox_redteam=True)
    sb = SandboxReplay(guard, replica="10.0.0.5")
    with pytest.raises(ModeViolation):
        sb.validate("bad", ["docker", "run", "--network", sb.network, *extra])


# --------------------------------------------------------------------------- #
# F3: a validation must be bound to this sandbox, not an arbitrary host
# --------------------------------------------------------------------------- #
def test_free_form_command_not_bound_to_sandbox_refused(make_env):
    guard = _guard(make_env, enable_sandbox_redteam=True)
    sb = SandboxReplay(guard, replica="10.0.0.5")
    # a curl at an arbitrary host references neither the network nor the project
    with pytest.raises(ModeViolation):
        sb.validate("curl", ["curl", "https://example.com"])


def test_docker_run_without_sandbox_network_refused(make_env):
    guard = _guard(make_env, enable_sandbox_redteam=True)
    sb = SandboxReplay(guard, replica="10.0.0.5")
    # references the project name somewhere, but a docker run must bind --network
    with pytest.raises(ModeViolation):
        sb.validate("x", ["docker", "run", "--rm", "busybox", sb.project])


def test_compose_exec_validation_is_allowed(make_env):
    guard = _guard(make_env, enable_sandbox_redteam=True)
    sb = SandboxReplay(guard, replica="10.0.0.5")
    res = sb.validate("exec", ["docker", "compose", "-p", sb.project, "exec", "-T", "web", "true"])
    assert res.dry_run is True  # bound via the project; accepted


# --------------------------------------------------------------------------- #
# network isolation
# --------------------------------------------------------------------------- #
def test_network_is_internal_and_dedicated(make_env):
    guard = _guard(make_env, enable_sandbox_redteam=True)
    sb = SandboxReplay(guard, replica="10.0.0.5")
    create = sb.up_commands()[0]
    assert create[:3] == ["docker", "network", "create"]
    assert "--internal" in create
    assert sb.network.startswith("sentinel_sbx_")


# --------------------------------------------------------------------------- #
# F1/F2: compose files are parsed structurally and refused on any hole
# --------------------------------------------------------------------------- #
def _compose(tmp_path, body: str) -> str:
    p = tmp_path / "compose.yaml"
    p.write_text(body, encoding="utf-8")
    return str(p)


_INTERNAL_OK = """
services:
  web:
    image: nginx
    networks: [sandbox]
networks:
  sandbox:
    internal: true
"""


def test_compose_internal_only_is_accepted(make_env, tmp_path):
    guard = _guard(make_env, enable_sandbox_redteam=True)
    cf = _compose(tmp_path, _INTERNAL_OK)
    sb = SandboxReplay(guard, replica="10.0.0.5", compose_file=cf)
    cmds = sb.up()  # must not raise, even in dry-run
    assert any(c[:2] == ["docker", "compose"] for c in cmds)


def test_compose_rejects_docker_socket_mount(make_env, tmp_path):
    guard = _guard(make_env, enable_sandbox_redteam=True)
    body = """
services:
  web:
    image: nginx
    networks: [sandbox]
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
networks:
  sandbox:
    internal: true
"""
    sb = SandboxReplay(guard, replica="10.0.0.5", compose_file=_compose(tmp_path, body))
    with pytest.raises(ModeViolation, match="sensitive host path"):
        sb.up()


def test_compose_rejects_cap_add(make_env, tmp_path):
    guard = _guard(make_env, enable_sandbox_redteam=True)
    body = """
services:
  web:
    image: nginx
    networks: [sandbox]
    cap_add: [SYS_ADMIN]
networks:
  sandbox:
    internal: true
"""
    sb = SandboxReplay(guard, replica="10.0.0.5", compose_file=_compose(tmp_path, body))
    with pytest.raises(ModeViolation, match="cap_add"):
        sb.up()


def test_compose_rejects_non_internal_network(make_env, tmp_path):
    guard = _guard(make_env, enable_sandbox_redteam=True)
    body = """
services:
  web:
    image: nginx
    networks: [sandbox]
networks:
  sandbox: {}
"""
    sb = SandboxReplay(guard, replica="10.0.0.5", compose_file=_compose(tmp_path, body))
    with pytest.raises(ModeViolation, match="internal: true"):
        sb.up()


def test_compose_rejects_default_network(make_env, tmp_path):
    guard = _guard(make_env, enable_sandbox_redteam=True)
    body = """
services:
  web:
    image: nginx
"""
    sb = SandboxReplay(guard, replica="10.0.0.5", compose_file=_compose(tmp_path, body))
    with pytest.raises(ModeViolation, match="default bridge"):
        sb.up()


def test_compose_rejects_published_ports(make_env, tmp_path):
    guard = _guard(make_env, enable_sandbox_redteam=True)
    body = """
services:
  web:
    image: nginx
    networks: [sandbox]
    ports:
      - "8080:80"
networks:
  sandbox:
    internal: true
"""
    sb = SandboxReplay(guard, replica="10.0.0.5", compose_file=_compose(tmp_path, body))
    with pytest.raises(ModeViolation, match="ports"):
        sb.up()


@pytest.mark.parametrize(
    "snippet,match",
    [
        ("privileged: true", "privileged"),
        ("network_mode: host", "network_mode"),
        ("pid: host", "pid"),
        ("userns_mode: host", "userns_mode"),
    ],
)
def test_compose_rejects_escalation_keys(make_env, tmp_path, snippet, match):
    guard = _guard(make_env, enable_sandbox_redteam=True)
    body = f"""
services:
  web:
    image: nginx
    networks: [sandbox]
    {snippet}
networks:
  sandbox:
    internal: true
"""
    sb = SandboxReplay(guard, replica="10.0.0.5", compose_file=_compose(tmp_path, body))
    with pytest.raises(ModeViolation, match=match):
        sb.up()


def test_compose_malformed_yaml_refused(make_env, tmp_path):
    guard = _guard(make_env, enable_sandbox_redteam=True)
    sb = SandboxReplay(guard, replica="10.0.0.5", compose_file=_compose(tmp_path, "a: [1, 2\n  bad"))
    with pytest.raises(ModeViolation):
        sb.up()


# --------------------------------------------------------------------------- #
# lifecycle / audit
# --------------------------------------------------------------------------- #
def test_replay_tears_down_even_if_validation_runs(make_env):
    guard = _guard(make_env, enable_sandbox_redteam=True)
    sb = SandboxReplay(guard, replica="10.0.0.5")
    plan = sb.replay([("probe", _run(sb, "busybox", "true"))])
    assert plan.dry_run is True
    assert any("network rm" in c for c in plan.down_commands)
    events = [e["event"] for e in _audit_events(guard)]
    assert "sandbox.up.plan" in events
    assert "sandbox.validate.plan" in events
    assert "sandbox.down.plan" in events
