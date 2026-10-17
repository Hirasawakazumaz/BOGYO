"""Shared fixtures: build a fully-signed, consented environment in a tmp dir."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import pytest

from sentinel.core.config import Limits, Paths, ScopeDoc, Settings, Toggles
from sentinel.core.consent import ACCEPT_PHRASE, REQUIRED_CLAUSES, ensure_consent_keypair, write_consent
from sentinel.core.signing import generate_keypair, load_private_key, sign


@dataclass
class Env:
    settings: Settings
    scope: ScopeDoc
    root: Path


def _write_scope(root: Path) -> ScopeDoc:
    scope = ScopeDoc(
        owner_name="Tester",
        owner_org="TestOrg",
        allowed_hosts=["web01.test.internal", "203.0.113.10"],
        allowed_cidrs=["203.0.113.0/24", "10.0.0.0/24"],
        production_hosts=["web01.test.internal", "203.0.113.0/24"],
        created_at="2026-10-17",
        nonce="fixed-test-nonce",
    )
    cfg = root / "config"
    cfg.mkdir(parents=True, exist_ok=True)
    (cfg / "scope.yaml").write_text(scope.model_dump_json(indent=2), encoding="utf-8")
    # sign
    generate_keypair(cfg / "scope.key", cfg / "scope.pub")
    priv = load_private_key(cfg / "scope.key")
    (cfg / "scope.yaml.sig").write_bytes(sign(priv, scope.canonical()))
    return scope


def _write_consent(root: Path, scope: ScopeDoc) -> None:
    cfg = root / "config"
    ensure_consent_keypair(cfg / "consent.key", cfg / "consent.pub")
    write_consent(
        scope=scope,
        operator_name="Tester",
        operator_org="TestOrg",
        accepted_clauses=list(REQUIRED_CLAUSES.keys()),
        accept_phrase=ACCEPT_PHRASE,
        private_key_path=cfg / "consent.key",
        out_path=cfg / "consent.signed",
    )


@pytest.fixture
def make_env(tmp_path):
    """Factory: make_env(**toggle_overrides) -> Env with signed scope + consent."""

    def _factory(dry_run: bool = True, **toggles) -> Env:
        root = tmp_path
        scope = _write_scope(root)
        _write_consent(root, scope)
        cfg = root / "config"
        settings = Settings(
            dry_run=dry_run,
            toggles=Toggles(**toggles),
            limits=Limits(),
            paths=Paths(
                scope_file=str(cfg / "scope.yaml"),
                scope_sig_file=str(cfg / "scope.yaml.sig"),
                scope_pubkey_file=str(cfg / "scope.pub"),
                consent_file=str(cfg / "consent.signed"),
                consent_pubkey_file=str(cfg / "consent.pub"),
                audit_file=str(root / "state" / "audit.jsonl"),
                killswitch_file=str(root / "state" / "KILL"),
                state_dir=str(root / "state"),
            ),
        )
        return Env(settings=settings, scope=scope, root=root)

    return _factory
