"""Minimal HTTP transport for the own-server mesh (stdlib only, no extra deps).

Each exchange is a short session: the client picks a random salt, both sides
derive the same per-session key from the pair's X25519 root + salt, and the
rolling-key channel advances per message (client sends blocks, server replies
with encrypted acks). This keeps the "key changes with the exchanged data"
property while staying robust across restarts (no long-lived ratchet to desync).

A received block is recorded ``applied`` only if ``checker`` approves it — normally
a :class:`~sentinel.mesh.gate.ConflictGate` over the sandbox ConflictEvaluator.
With no checker, nothing is applied (blocks stay ``shared``, fail closed).

Security note: this carries the authenticated, doubly-encrypted channel; the HTTP
layer itself is just a pipe. Run it only between your own servers (ideally over a
private network / WireGuard), as the consent requires.
"""

from __future__ import annotations

import json
import secrets
import threading
import urllib.request
from dataclasses import asdict
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Callable, Optional

from .chain import Block
from .node import MeshNode
from .ratchet import RatchetChannel, RatchetError, derive_root

PATH = "/mesh"


def _deny_all(_block: Block) -> bool:
    """Default checker: without a real conflict gate nothing is applied (fail closed)."""
    return False


def _apply_incoming(node: MeshNode, peer_name: str, block_dict: dict,
                    checker: Callable[[Block], bool]) -> dict:
    """Verify a received block, add it to the chain, and conflict-gate apply."""
    block = Block(**block_dict)
    if not block.verify():
        return {"status": "rejected", "reason": "bad signature"}
    rebased = node.chain.make_block(node.identity, block.domain, {
        "shared_ref": block.hash, "author": block.author, **block.payload
    }, status="shared")
    node.chain.append(rebased)
    try:
        decision = checker(rebased)  # e.g. a ConflictGate (GateDecision) or a plain bool
    except Exception:  # noqa: BLE001 - a crashing checker must never let a patch through
        decision = False
    if decision:
        node.consider_apply(rebased, lambda _b: True)
        return {"status": "applied", "ref": rebased.hash}
    ack = {"status": "shared", "ref": rebased.hash}
    reason = getattr(decision, "reason", "")
    if reason:
        ack["reason"] = reason
    return ack


class _Handler(BaseHTTPRequestHandler):
    node: MeshNode = None            # set on the server instance
    checker: Callable[[Block], bool] = staticmethod(_deny_all)

    def log_message(self, *a):  # silence default logging
        pass

    def do_POST(self):
        if self.path != PATH:
            self.send_response(404); self.end_headers(); return
        try:
            length = int(self.headers.get("Content-Length", 0))
            req = json.loads(self.rfile.read(length).decode())
            peer_name = req["peer"]
            salt = bytes.fromhex(req["salt"])
            peer = self.node.peers[peer_name]
            ch = RatchetChannel(derive_root(self.node.identity, peer.x25519_pub),
                                self.node.window, salt)
            acks = []
            for msg in req["blocks"]:
                block_dict = ch.decrypt_json(msg, peer.ed25519_pub)
                result = _apply_incoming(self.node, peer_name, block_dict, self.checker)
                acks.append(ch.encrypt_json(result, self.node.identity))
            body = json.dumps({"acks": acks}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        except (KeyError, ValueError, RatchetError) as exc:
            msg = json.dumps({"error": type(exc).__name__}).encode()
            self.send_response(400)
            self.send_header("Content-Length", str(len(msg)))
            self.end_headers()
            self.wfile.write(msg)


def make_server(node: MeshNode, host: str, port: int,
                checker: Optional[Callable[[Block], bool]] = None) -> ThreadingHTTPServer:
    handler = type("_H", (_Handler,), {"node": node,
                                       "checker": staticmethod(checker or _deny_all)})
    return ThreadingHTTPServer((host, port), handler)


def serve(node: MeshNode, host: str, port: int,
          checker: Optional[Callable[[Block], bool]] = None, background: bool = False):
    srv = make_server(node, host, port, checker)
    if background:
        th = threading.Thread(target=srv.serve_forever, daemon=True)
        th.start()
        return srv
    srv.serve_forever()
    return srv


def push(node: MeshNode, peer_name: str, endpoint: str, blocks: list[Block],
         timeout: float = 20.0) -> list[dict]:
    """Send blocks to a peer's endpoint over a fresh rolling-key session; return acks."""
    peer = node.peers[peer_name]
    salt = secrets.token_bytes(16)
    ch = RatchetChannel(derive_root(node.identity, peer.x25519_pub), node.window, salt)
    msgs = [ch.encrypt_json(asdict(b), node.identity) for b in blocks]
    payload = json.dumps({"peer": node.identity.name, "salt": salt.hex(), "blocks": msgs}).encode()
    url = endpoint.rstrip("/") + PATH
    req = urllib.request.Request(url, data=payload, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 - operator's own host
        data = json.loads(resp.read().decode())
    return [ch.decrypt_json(a, peer.ed25519_pub) for a in data.get("acks", [])]
