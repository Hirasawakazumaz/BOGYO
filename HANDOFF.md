# Sentinel-Guard — HANDOFF

Living status doc. Update + commit (and push to the private GitHub repo) at every milestone.

## What this is
Authorized, **consent-gated, fail-closed** proactive defense & self-pentest orchestration
for Linux servers — for assets **you own or are explicitly authorized to test** only.
Finds/fixes vulnerabilities before attackers, auto-blocks attacking IPs, validates findings
in isolated Docker sandboxes, proposes/evaluates patches, and shows it all on a cyber
world-map dashboard.

## Where / how to run
- Path: your checkout of the repository.
- Env: `. .venv/bin/activate`; tests: `python -m pytest -q`.
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

## Status (as of 2026-10-18)
Branch `main`, all tests green: **85 passed**. Latest additions:
- Real Anthropic token accounting wired into the usage Governor (`d292219`): budget
  picks the model tier and stops/resumes; offline rule fallback when stopped.
- i18n (en/ja) chosen at `sentinel init` (`ui.language`) + a machine-readable control
  API `sentinel config dump|get|set` and `sentinel state --json` so other apps can read
  and change every display/settings item (`4a0be38`). `geo.static_map {ip: ISO2}` gives
  offline deterministic IP→country (also powers the offline live demo).
- **Live demo** (separate path, NOT in the repo): `a separate local demo directory` —
  `bash setup_demo.sh`, then `bash run_feed.sh` (terminal A) + `bash run_dashboard.sh`
  (terminal B). See its `README_DEMO.md`.

Commits on top of v0.1 (`60ff6b9`):
- `6986dd3` sandbox replay (Phase 4)
- `3b66780` patch proposer + conflict-eval loop (Phase 5)
- `a175fb7` graph/schedule/report (Phase 6)
- `553e7a6` docs for Phases 4-6
- `e09dc14` graph skip fix
- `3a3c518` **sandbox isolation hardening (F1/F2/F3)** via YAML structural analysis
- (this milestone) **cyber dashboard + usage governor + geo** — see below

### This milestone: dashboard, usage governor, geo
- `sentinel/usage/` — `UsageLedger` (token ledger) + `Governor`: daily token budget drives
  automatic model downgrade (tiers) → frequency throttle → stop, auto-resume at local
  midnight. Provider `api` (metered) or `cli` (subscription, no token-stop). `sentinel usage`.
- `sentinel/intel/geo.py` — IP→country via a keyless public API (opt-in; private IPs never
  sent; offline → unknown) + country centroids for the map.
- `sentinel/dashboard/` — `DashboardModel` aggregates the audit log + usage + geo;
  `worldmap.py` renders the ASCII world map with attacker→home arrows (blocked `x` / active
  `!` / home `@`); `snapshot.py` prints a plain CASIO-watch/cyber panel (no deps);
  `app.py` is the interactive Textual UI (green/cyan cyber theme, live refresh, **config
  screen** to edit settings from the TUI). `sentinel dashboard [--once]`.
- Settings gained `usage:` and `geo:` sections; `Settings.save()` lets the TUI persist them.

## How to use (operator)
`sentinel init` → edit `config/scope.yaml` (owned assets only) → `keygen` → `sign-scope` →
`consent` → `status`/`verify`. Then `block`/`scan`/`sandbox`/`patch`/`schedule`/`report`,
`usage`, and `dashboard`. Enable real actions only after reviewing dry-run output
(`dry_run: false` + the specific toggle).

## Known follow-ups / not done
- `apply_to_host` writes the **local** file at `candidate.path` (host arg is scope-check +
  audit only); no backup before overwrite. Fine for local, misleading for remote hosts.
- `SandboxReplay.up()/down()` (docker network/compose) are not themselves toggle-gated
  (only the attack `validate()` is). Benign (standing up your own container) but noted.
- Dashboard geo lookups run inline on refresh; with many IPs + geo enabled, consider a
  background worker.
- LLM token accounting is wired through `Governor.record(...)`; connect the Anthropic
  backend's real response usage to it when running with `[agent]`.
- Not yet pushed to GitHub as of the pre-dashboard commits; repo is **private**.
