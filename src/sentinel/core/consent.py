"""Operator consent / ownership attestation.

Before any capability runs, the operator must sign a consent record that is
bound to the current scope hash. Changing the scope changes its hash, which
invalidates the old consent and forces re-consent.

The consent file stores the record plus an Ed25519 signature. Verification is
fail-closed: a missing clause, a scope-hash mismatch, or a bad signature all
raise :class:`ConsentRequired`.
"""

from __future__ import annotations

import json
import secrets
from datetime import datetime, timezone
from pathlib import Path

from pydantic import BaseModel, Field

from .. import __version__
from .config import ScopeDoc
from .errors import ConsentRequired, SigningError
from .signing import (
    canonical_bytes,
    generate_keypair,
    load_private_key,
    load_public_key,
    sign,
    verify,
)

#: Clauses the operator must explicitly accept. All are required.
REQUIRED_CLAUSES: dict[str, str] = {
    "ownership": (
        "I attest that I own or am explicitly authorized to test every host and "
        "network listed in the scope. / スコープに記載の全ホスト・ネットワークを"
        "私が所有、または明示的にテスト許可を得ていることを誓約します。"
    ),
    "no_third_party": (
        "I will not point this tool at any system I do not own/control, and I will "
        "not use it to attack or retaliate against third parties. / 第三者のシステムへ"
        "の使用・攻撃・反撃（ハックバック）を行いません。"
    ),
    "no_misuse_redistribution": (
        "I will not modify or redistribute this tool to remove its safeguards or to "
        "enable misuse. / 安全機構を除去・改変したり、悪用目的で再配布しません。"
    ),
    "legal_compliance": (
        "I will comply with all applicable laws (e.g. Japan Unauthorized Computer "
        "Access Act and Penal Code Art.168-2/168-3/234-2, US CFAA, UK CMA, DE StGB "
        "202c). / 関連法令（不正アクセス禁止法、刑法168条の2・3／234条の2、CFAA、"
        "CMA、独202c 等）を順守します。"
    ),
}

#: The operator must type this exact phrase to confirm.
ACCEPT_PHRASE = "I OWN THESE ASSETS AND ACCEPT THE TERMS"


class ConsentRecord(BaseModel):
    operator_name: str
    operator_org: str = ""
    scope_hash: str
    accepted_clauses: list[str] = Field(default_factory=list)
    accept_phrase: str = ""
    tool_version: str = __version__
    created_at: str = ""
    nonce: str = ""

    def canonical(self) -> bytes:
        return canonical_bytes(self.model_dump(mode="json"))


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def build_signed_consent(
    record: ConsentRecord,
    private_key_path: str | Path,
) -> dict:
    priv = load_private_key(Path(private_key_path))
    signature = sign(priv, record.canonical())
    return {"record": record.model_dump(mode="json"), "signature": signature.hex()}


def write_consent(
    *,
    scope: ScopeDoc,
    operator_name: str,
    operator_org: str,
    accepted_clauses: list[str],
    accept_phrase: str,
    private_key_path: str | Path,
    out_path: str | Path,
) -> ConsentRecord:
    """Validate acceptance, then write a signed consent file. Raises on refusal."""
    missing = [cid for cid in REQUIRED_CLAUSES if cid not in accepted_clauses]
    if missing:
        raise ConsentRequired(f"consent refused: unaccepted clauses {missing}")
    if accept_phrase.strip() != ACCEPT_PHRASE:
        raise ConsentRequired("consent refused: acceptance phrase did not match")

    record = ConsentRecord(
        operator_name=operator_name,
        operator_org=operator_org,
        scope_hash=scope.scope_hash(),
        accepted_clauses=sorted(set(accepted_clauses)),
        accept_phrase=accept_phrase.strip(),
        created_at=_now_iso(),
        nonce=secrets.token_hex(16),
    )
    bundle = build_signed_consent(record, private_key_path)
    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(bundle, ensure_ascii=False, indent=2), encoding="utf-8")
    return record


def verify_consent(
    consent_file: str | Path,
    pubkey_file: str | Path,
    expected_scope_hash: str,
) -> ConsentRecord:
    """Load + verify consent against the current scope. Fail closed."""
    consent_file = Path(consent_file)
    pubkey_file = Path(pubkey_file)
    if not consent_file.exists():
        raise ConsentRequired(f"no consent file: {consent_file} (run `sentinel consent`)")
    if not pubkey_file.exists():
        raise ConsentRequired(f"no consent public key: {pubkey_file}")

    try:
        bundle = json.loads(consent_file.read_text(encoding="utf-8"))
        record = ConsentRecord.model_validate(bundle["record"])
        signature = bytes.fromhex(bundle["signature"])
    except Exception as exc:  # noqa: BLE001
        raise ConsentRequired(f"malformed consent file: {exc}") from exc

    pub = load_public_key(pubkey_file)
    try:
        verify(pub, record.canonical(), signature)
    except SigningError as exc:
        raise ConsentRequired(f"consent signature invalid: {exc}") from exc

    missing = [cid for cid in REQUIRED_CLAUSES if cid not in record.accepted_clauses]
    if missing:
        raise ConsentRequired(f"consent missing required clauses: {missing}")
    if record.accept_phrase != ACCEPT_PHRASE:
        raise ConsentRequired("consent acceptance phrase mismatch")
    if record.scope_hash != expected_scope_hash:
        raise ConsentRequired(
            "scope changed since consent was signed — re-run `sentinel consent`"
        )
    return record


def ensure_consent_keypair(private_path: str | Path, public_path: str | Path) -> None:
    """Create an operator consent keypair if the private key does not yet exist."""
    private_path, public_path = Path(private_path), Path(public_path)
    if not private_path.exists():
        private_path.parent.mkdir(parents=True, exist_ok=True)
        generate_keypair(private_path, public_path)
