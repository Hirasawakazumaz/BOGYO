"""Consent binding, scope-signature verification, and tamper detection."""

from __future__ import annotations

import pytest

from sentinel.core.config import load_verified_scope
from sentinel.core.consent import verify_consent
from sentinel.core.errors import ConsentRequired, SigningError
from sentinel.guards import ScopeGuard


def test_consent_verifies_against_scope(make_env):
    env = make_env()
    rec = verify_consent(
        env.settings.paths.consent_file,
        env.settings.paths.consent_pubkey_file,
        env.scope.scope_hash(),
    )
    assert rec.operator_name == "Tester"


def test_scope_change_invalidates_consent(make_env):
    env = make_env()
    # Tamper with the scope file (add a host) WITHOUT re-signing.
    scope_path = env.settings.paths.scope_file
    with open(scope_path, "r+", encoding="utf-8") as fh:
        data = fh.read().replace("web01.test.internal", "attacker-added.host")
        fh.seek(0)
        fh.write(data)
        fh.truncate()
    # Signature no longer matches -> fail closed at load (SigningError is a SentinelError).
    with pytest.raises(SigningError):
        load_verified_scope(
            env.settings.paths.scope_file,
            env.settings.paths.scope_sig_file,
            env.settings.paths.scope_pubkey_file,
        )


def test_missing_consent_refused(make_env):
    env = make_env()
    import os

    os.remove(env.settings.paths.consent_file)
    with pytest.raises(ConsentRequired):
        ScopeGuard.from_settings(env.settings)


def test_tampered_consent_signature_refused(make_env):
    env = make_env()
    # Flip a byte in the signed record.
    p = env.settings.paths.consent_file
    import json

    bundle = json.loads(open(p, encoding="utf-8").read())
    bundle["record"]["operator_name"] = "Mallory"
    open(p, "w", encoding="utf-8").write(json.dumps(bundle))
    with pytest.raises(ConsentRequired):
        verify_consent(p, env.settings.paths.consent_pubkey_file, env.scope.scope_hash())
