# BOGYO — HANDOFF

Living status doc for contributors. Update it at every milestone.

## What this is
Authorized, **consent-gated, fail-closed** proactive defense & self-pentest orchestration
for Linux servers — for assets **you own or are explicitly authorized to test** only.
Finds/fixes vulnerabilities before attackers, auto-blocks attacking IPs, validates findings
in isolated Docker sandboxes, proposes/evaluates patches, shares patches across your own
servers, and shows it all on a cyber dashboard.

## How to run
- `python3 -m venv .venv && . .venv/bin/activate && pip install -e ".[dev]"`
- Tests: `python -m pytest -q` (CI runs them on Python 3.11–3.13: `.github/workflows/ci.yml`).
- Extras: `pip install -e ".[agent]"` (LangGraph/LLM), `".[tui]"` (Textual dashboard). Core
  + plain snapshot run without either.

## Safety model (non-negotiable)
Every active capability routes through the single guard `sentinel.guards.ScopeGuard`
(no bypass flag). Fail-closed on: unsigned/invalid scope, consent not matching scope hash,
kill-switch present, out-of-scope target, redteam on production or outside a sandbox,
disabled toggle. Default-deny toggles, `dry_run` default on. No hack-back. Tamper-evident
hash-chained audit log. Sandbox isolation is **enforced by YAML structural analysis** of
the compose file (internal-only networks; refuses docker-socket/host binds, cap_add,
devices, unconfined security_opt, host namespaces, privileged, published ports); validation
commands must be bound to the sandbox network.

Never commit secrets or local state: keys, consent, `config/scope.yaml`,
`config/settings.yaml`, `state/` are gitignored, and CI fails if any is tracked.

## Status
The project is named **BOGYO** (formerly Sentinel-Guard); the package `sentinel` and
the `sentinel` command keep their names (alias `bogyo`).

All tests green (115). Recent milestones:
- CLI output goes through one English string table (`sentinel/i18n.py`). The UI is
  English-only; a legacy `ui.language` value is accepted and resolves to English.
- **Mesh conflict gate** (`sentinel/mesh/gate.py`): a peer's patch is recorded `applied`
  only if the local sandbox `ConflictEvaluator` actually ran its checks and all passed.
  Dry-run, no checks, missing patch content, hash mismatch, or any guard refusal keep it
  `shared`. Transport default denies. `mesh serve` builds the ScopeGuard first and takes
  `--replica/--compose/--check` (checks are local only, never from a peer).
- **RuleBackend** hardening rules for sshd / nginx / postgres / sysctl; missing directives
  are inserted at a safe spot (sshd: before the first `Match`; nginx: inside `http {}`);
  rules only ever tighten and are idempotent.
- Usage governor (daily token budget → model downgrade → throttle → stop), control API
  (`sentinel config dump|get|set`, `sentinel state --json`), dashboard (TUI + snapshot),
  sandbox replay, patch loop, graph/schedule/report.

## How to use (operator)
`sentinel init` → edit `config/scope.yaml` (owned assets only) → `keygen` → `sign-scope` →
`consent` → `status`/`verify`. Then `block`/`scan`/`sandbox`/`patch`/`schedule`/`report`,
`usage`, `dashboard`, and `mesh`. Enable real actions only after reviewing dry-run output
(`dry_run: false` + the specific toggle).

## Known follow-ups / not done
- `mesh propose` blocks carry metadata only (no `hardened` content), so the conflict gate
  never applies them; add content + `hardened_sha256` generation to `propose`.
- `ConflictEvaluator` runs its checks but does not first write the candidate into the
  sandbox replica; `--check` commands are escalation-checked but not required to be bound
  to the sandbox network.
- `apply_to_host` writes the **local** file at `candidate.path` (host arg is scope-check +
  audit only); no backup before overwrite. Fine for local, misleading for remote hosts.
- `SandboxReplay.up()/down()` are not themselves toggle-gated (only `validate()` is).
- Dashboard geo lookups run inline on refresh; consider a background worker.
