"""Mesh: machine-bound identity, rolling-key channel, signed chain, gated apply."""

from __future__ import annotations

import hashlib

import pytest

from sentinel.core import killswitch
from sentinel.core.errors import SigningError
from sentinel.guards import ScopeGuard
from sentinel.mesh import (
    Block, ConflictGate, MeshNode, NodeIdentity, PatchChain, RatchetChannel, RatchetError, derive_root,
)
from sentinel.patch import ConflictEvaluator


# -- identity --------------------------------------------------------------- #
def test_identity_roundtrip_same_machine(tmp_path):
    idn = NodeIdentity.create("A")
    p = tmp_path / "node.key.enc"
    idn.save(p, "pass123")
    back = NodeIdentity.load(p, "pass123")
    assert back.ed25519_pub() == idn.ed25519_pub()
    assert back.x25519_pub() == idn.x25519_pub()


def test_identity_wrong_passphrase_refused(tmp_path):
    idn = NodeIdentity.create("A")
    p = tmp_path / "node.key.enc"
    idn.save(p, "right")
    with pytest.raises(SigningError):
        NodeIdentity.load(p, "wrong")  # also the path that fails on a different machine


# -- ratchet ---------------------------------------------------------------- #
def _pair():
    a, b = NodeIdentity.create("A"), NodeIdentity.create("B")
    ca = RatchetChannel(derive_root(a, b.x25519_pub()), 30)
    cb = RatchetChannel(derive_root(b, a.x25519_pub()), 30)
    return a, b, ca, cb


def test_ratchet_roundtrip_and_key_rolls():
    a, _b, ca, cb = _pair()
    m1 = ca.encrypt_json({"hi": 1}, a)
    assert cb.decrypt_json(m1, a.ed25519_pub()) == {"hi": 1}
    m2 = ca.encrypt_json({"hi": 2}, a)
    assert cb.decrypt_json(m2, a.ed25519_pub()) == {"hi": 2}
    # replaying the first message is rejected: the key has rolled forward
    with pytest.raises(RatchetError):
        cb.decrypt_json(m1, a.ed25519_pub())


def test_ratchet_tamper_rejected():
    a, _b, ca, cb = _pair()
    m = ca.encrypt(b"secret", a)
    m["ct"] = "00" + m["ct"][2:]
    with pytest.raises(RatchetError):
        cb.decrypt(m, a.ed25519_pub())


def test_ratchet_wrong_key_rejected():
    a, _b, ca, _cb = _pair()
    c = NodeIdentity.create("C")
    wrong = RatchetChannel(derive_root(c, a.x25519_pub()), 30)  # different shared root
    m = ca.encrypt(b"x", a)
    with pytest.raises(RatchetError):
        wrong.decrypt(m, a.ed25519_pub())


# -- chain ------------------------------------------------------------------ #
def test_chain_append_validate_and_tamper_detection():
    a = NodeIdentity.create("A")
    ch = PatchChain()
    ch.append(ch.make_block(a, "sshd", {"finding": "F1"}))
    ch.append(ch.make_block(a, "sshd", {"finding": "F2"}))
    assert ch.validate() and ch.height() == 2
    ch.blocks[0].payload["finding"] = "evil"
    assert ch.validate() is False


# -- node loopback ---------------------------------------------------------- #
def test_mesh_share_and_conflict_gated_apply():
    a, b = NodeIdentity.create("A"), NodeIdentity.create("B")
    na, nb = MeshNode(a, "sshd"), MeshNode(b, "nginx")
    na.add_peer("B", b.ed25519_pub(), b.x25519_pub(), "nginx")
    nb.add_peer("A", a.ed25519_pub(), a.x25519_pub(), "sshd")

    block = na.propose({"finding": "F-ssh", "service": "sshd",
                        "path": "/etc/ssh/sshd_config", "hardened_sha256": "abc"})
    shared = nb.ingest("A", na.encode_for("B", block))
    assert shared.payload.get("shared_ref") == block.hash
    assert len(nb.chain.pending()) >= 1

    ack = nb.consider_apply(shared, lambda blk: True)      # conflict check passes
    assert ack is not None and ack.status == "applied"

    block2 = na.propose({"finding": "F2"})
    shared2 = nb.ingest("A", na.encode_for("B", block2))
    assert nb.consider_apply(shared2, lambda blk: False) is None  # conflict -> not applied


def test_transport_push_over_http_loopback():
    from sentinel.mesh import push, serve

    a, b = NodeIdentity.create("A"), NodeIdentity.create("B")
    na, nb = MeshNode(a, "sshd"), MeshNode(b, "nginx")
    na.add_peer("B", b.ed25519_pub(), b.x25519_pub(), "nginx")
    nb.add_peer("A", a.ed25519_pub(), a.x25519_pub(), "sshd")

    srv = serve(nb, "127.0.0.1", 0, background=True)  # OS-assigned port
    try:
        port = srv.server_address[1]
        block = na.propose({"service": "sshd", "finding": "F1", "path": "/etc/ssh/sshd_config"})
        acks = push(na, "B", f"http://127.0.0.1:{port}", [block])
    finally:
        srv.shutdown()
    assert acks and acks[0]["status"] in ("applied", "shared")
    assert nb.chain.height() >= 1
    assert nb.chain.validate()


# -- conflict gate (real sandbox ConflictEvaluator, fail closed) ------------- #
HARDENED = "PermitRootLogin no\nPasswordAuthentication no\n"
CHECKS = [("startup:restart", ["docker", "compose", "-p", "sentinel_sbx_x", "restart", "sshd"])]


def _patch_block(node, hardened=HARDENED, **extra):
    payload = {"service": "sshd", "finding": "F-ssh", "path": "/etc/ssh/sshd_config",
               "original": "PermitRootLogin yes\n", "hardened": hardened,
               "hardened_sha256": hashlib.sha256(hardened.encode()).hexdigest()}
    payload.update(extra)
    return node.propose(payload)


def _gate(make_env, *, dry_run, rc=0, checks=CHECKS):
    env = make_env(dry_run=dry_run)
    guard = ScopeGuard.from_settings(env.settings)
    calls = []

    def runner(args):
        calls.append(args)
        return rc, ""

    return ConflictGate(ConflictEvaluator(guard, runner=runner), checks), calls, env


def _pair_nodes():
    a, b = NodeIdentity.create("A"), NodeIdentity.create("B")
    na, nb = MeshNode(a, "sshd"), MeshNode(b, "nginx")
    na.add_peer("B", b.ed25519_pub(), b.x25519_pub(), "nginx")
    nb.add_peer("A", a.ed25519_pub(), a.x25519_pub(), "sshd")
    return na, nb


def _push_via_http(na, nb, block, checker=None):
    from sentinel.mesh import push, serve

    srv = serve(nb, "127.0.0.1", 0, checker=checker, background=True)
    try:
        return push(na, "B", f"http://127.0.0.1:{srv.server_address[1]}", [block])
    finally:
        srv.shutdown()


def test_transport_without_checker_never_applies():
    na, nb = _pair_nodes()
    acks = _push_via_http(na, nb, _patch_block(na))
    assert acks[0]["status"] == "shared"
    assert nb.chain.applied() == []


def test_gate_live_checks_pass_applies_over_http(make_env):
    gate, calls, _ = _gate(make_env, dry_run=False, rc=0)
    na, nb = _pair_nodes()
    acks = _push_via_http(na, nb, _patch_block(na), checker=gate)
    assert acks[0]["status"] == "applied"
    assert calls == [CHECKS[0][1]]          # the operator's local check, run once
    assert len(nb.chain.applied()) == 1 and nb.chain.validate()


def test_gate_live_conflict_keeps_shared(make_env):
    gate, _, _ = _gate(make_env, dry_run=False, rc=1)
    na, nb = _pair_nodes()
    acks = _push_via_http(na, nb, _patch_block(na), checker=gate)
    assert acks[0]["status"] == "shared" and "startup:restart" in acks[0]["reason"]
    assert nb.chain.applied() == []


def test_gate_dry_run_never_applies(make_env):
    gate, calls, _ = _gate(make_env, dry_run=True)
    na, _nb = _pair_nodes()
    d = gate(_patch_block(na))
    assert not d and d.dry_run and "dry-run" in d.reason
    assert calls == []                      # nothing executed in dry-run


def test_gate_refuses_missing_content_and_bad_hash(make_env):
    gate, calls, _ = _gate(make_env, dry_run=False)
    na, _nb = _pair_nodes()
    assert "no patch content" in gate(na.propose({"service": "sshd", "finding": "F1"})).reason
    bad = _patch_block(na, hardened_sha256="0" * 64)
    assert "mismatch" in gate(bad).reason
    assert calls == []


def test_gate_refuses_when_no_checks(make_env):
    gate, _, _ = _gate(make_env, dry_run=False, checks=[])
    na, _nb = _pair_nodes()
    d = gate(_patch_block(na))
    assert not d and "no conflict checks" in d.reason


def test_gate_fails_closed_on_kill_switch_and_escalation(make_env):
    gate, calls, env = _gate(make_env, dry_run=False,
                             checks=[("startup", ["docker", "run", "--privileged", "x"])])
    na, _nb = _pair_nodes()
    assert "ModeViolation" in gate(_patch_block(na)).reason

    gate2 = ConflictGate(gate.evaluator, CHECKS)
    killswitch.engage(env.settings.paths.killswitch_file, reason="test")
    d = gate2(_patch_block(na))
    assert not d and "refused" in d.reason
    assert calls == []


def test_cli_mesh_serve_fails_closed_before_listening(make_env, tmp_path, monkeypatch):
    from pathlib import Path

    import sentinel.mesh as mesh_pkg
    from sentinel.cli.main import main

    monkeypatch.setattr(mesh_pkg, "serve", lambda *a, **k: pytest.fail("must not serve"))
    env = make_env()
    sp = str(tmp_path / "settings.yaml")
    env.settings.save(sp)
    # production replica is refused before the node key is even loaded
    assert main(["mesh", "--settings", sp, "serve", "--replica", "web01.test.internal"]) == 1
    # no valid consent -> the guard refuses, so the endpoint never starts
    Path(env.settings.paths.consent_file).unlink()
    assert main(["mesh", "--settings", sp, "serve", "--passphrase", "x"]) == 2
