"""Reproduce the measurements in docs/publication/03_paper.md (Section 8).

Usage (from the repository root, inside the project venv):

    python docs/publication/eval/bench_audit_guard.py

Everything runs in temporary directories; nothing touches the network, the
firewall, or the repository's own config/ and state/.
"""

from __future__ import annotations

import json
import os
import platform
import random
import statistics
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tests"))

from conftest import _write_consent, _write_scope  # noqa: E402

from sentinel.core.actions import ActionClass  # noqa: E402
from sentinel.core.audit import AuditLog  # noqa: E402
from sentinel.core.config import Limits, Paths, Settings, Toggles  # noqa: E402
from sentinel.core.errors import GuardError  # noqa: E402
from sentinel.guards import ScopeGuard  # noqa: E402

N_ENTRIES = 10_000
TAMPER_TRIALS = 200
AUTH_CALLS = 2_000


def bench_audit(tmp: Path) -> tuple[dict, list[str]]:
    log = AuditLog(tmp / "audit.jsonl")
    t0 = time.perf_counter()
    for i in range(N_ENTRIES):
        log.append("bench", {"i": i, "ip": f"198.51.100.{i % 250}"})
    t1 = time.perf_counter()
    ok = log.verify_chain()
    t2 = time.perf_counter()
    lines = (tmp / "audit.jsonl").read_text(encoding="utf-8").splitlines()
    return {
        "append_us_per_entry": round((t1 - t0) / N_ENTRIES * 1e6, 1),
        "verify_ms_for_10k": round((t2 - t1) * 1e3, 1),
        "verify_ok": ok,
    }, lines


def tamper_trials(tmp: Path, lines: list[str], rng: random.Random) -> dict:
    detected = {"modify": 0, "delete": 0, "swap": 0}
    target = tmp / "tampered.jsonl"
    for kind in detected:
        for _ in range(TAMPER_TRIALS):
            work = list(lines)
            i = rng.randrange(0, len(work) - 1)
            if kind == "modify":
                entry = json.loads(work[i])
                entry["data"]["ip"] = "203.0.113.250"
                work[i] = json.dumps(entry, sort_keys=True)
            elif kind == "delete":
                del work[i]
            else:
                work[i], work[i + 1] = work[i + 1], work[i]
            target.write_text("\n".join(work) + "\n", encoding="utf-8")
            if not AuditLog(target).verify_chain():
                detected[kind] += 1
    return {"trials_each": TAMPER_TRIALS, "detected": detected}


def full_rewrite(tmp: Path) -> dict:
    """An attacker with write access drops entries and re-chains the rest."""
    log = AuditLog(tmp / "orig.jsonl")
    for i in range(1_000):
        log.append("block.apply", {"ip": f"198.51.100.{i % 250}"})
    witnessed_head = log._last_hash  # what an external witness would hold
    entries = [json.loads(x) for x in (tmp / "orig.jsonl").read_text(encoding="utf-8").splitlines()]
    forged = AuditLog(tmp / "forged.jsonl")
    for e in entries:
        if e["data"]["ip"] != "198.51.100.7":
            forged.append(e["event"], e["data"])
    return {
        "local_verify_passes": forged.verify_chain(),
        "detected_by_witnessed_head": forged._last_hash != witnessed_head,
    }


def bench_guard(tmp: Path) -> dict:
    scope = _write_scope(tmp)
    _write_consent(tmp, scope)
    cfg = tmp / "config"
    settings = Settings(
        dry_run=True,
        toggles=Toggles(enable_active_scan=True),
        limits=Limits(max_targets_per_run=4096, rate_per_minute=10_000),
        paths=Paths(
            scope_file=str(cfg / "scope.yaml"),
            scope_sig_file=str(cfg / "scope.yaml.sig"),
            scope_pubkey_file=str(cfg / "scope.pub"),
            consent_file=str(cfg / "consent.signed"),
            consent_pubkey_file=str(cfg / "consent.pub"),
            audit_file=str(tmp / "state" / "audit.jsonl"),
            killswitch_file=str(tmp / "state" / "KILL"),
            state_dir=str(tmp / "state"),
        ),
    )
    guard = ScopeGuard.from_settings(settings)

    def median_us(fn) -> float:
        samples = []
        for _ in range(AUTH_CALLS):
            s = time.perf_counter()
            fn()
            samples.append(time.perf_counter() - s)
        return round(statistics.median(samples) * 1e6, 1)

    def allow():
        guard.authorize(ActionClass.ACTIVE_SCAN, "10.0.0.5")

    def deny_scope():
        try:
            guard.authorize(ActionClass.ACTIVE_SCAN, "198.51.100.7")
        except GuardError:
            pass

    def deny_production():
        try:
            guard.authorize(ActionClass.REDTEAM_ATTACK, "203.0.113.10", environment="sandbox")
        except GuardError:
            pass

    return {
        "allow_median_us": median_us(allow),
        "deny_out_of_scope_median_us": median_us(deny_scope),
        "deny_redteam_production_median_us": median_us(deny_production),
        "audit_chain_intact_after": guard.audit.verify_chain(),
    }


def main() -> None:
    rng = random.Random(20261018)
    result = {
        "env": {
            "python": platform.python_version(),
            "machine": platform.machine(),
            "cpus": os.cpu_count(),
        }
    }
    with tempfile.TemporaryDirectory() as a, tempfile.TemporaryDirectory() as b, \
            tempfile.TemporaryDirectory() as c:
        result["audit"], lines = bench_audit(Path(a))
        result["tamper"] = tamper_trials(Path(a), lines, rng)
        result["full_rewrite"] = full_rewrite(Path(b))
        result["guard"] = bench_guard(Path(c))
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
