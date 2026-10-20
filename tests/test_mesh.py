"""Mesh: machine-bound identity, rolling-key channel, signed chain, gated apply."""

from __future__ import annotations

import pytest

from sentinel.core.errors import SigningError
from sentinel.mesh import (
    Block, MeshNode, NodeIdentity, PatchChain, RatchetChannel, RatchetError, derive_root,
)


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
