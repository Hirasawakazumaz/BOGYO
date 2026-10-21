# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/).

## [0.1.0] — 2026-10-21

First public release.

### Safety core
- Single authorization gate `ScopeGuard`: Ed25519-signed ownership scope, operator
  consent bound to the scope hash, kill-switch, default-deny capability toggles,
  `dry_run` on by default, rate/target/time-window limits. No bypass flag.
- Hash-chained, tamper-evident audit log (`sentinel verify`).

### Defense & testing
- Brute-force detection from auth logs and nftables blocking of attacking IPs
  (inbound drop only — no hack-back).
- Scan orchestration (nmap, nuclei) against in-scope hosts; passive CVE lookup.
- Docker sandbox replay for attack validation: sandbox-only, refused on production;
  isolation enforced by structural analysis of the compose file.
- Patch proposer (rules, local AI, or Claude) with a sandbox conflict-evaluation
  loop; host apply needs a toggle **and** explicit human approval.
- Rule-based hardening for sshd, nginx, postgres and sysctl: inserts missing
  directives at a safe spot, never weakens, idempotent.

### Own-server patch mesh
- Machine-bound, passphrase-encrypted node identity; rolling-key, doubly encrypted
  channel; signed, hash-linked patch chain; HTTP transport (`sentinel mesh`).
- A peer's patch is applied only after the local sandbox `ConflictEvaluator`
  actually ran and passed (fail closed in dry-run, without checks or content).

### Operations
- Claude usage governor: daily token budget → model downgrade → throttle → stop.
- Cyber dashboard (Textual TUI and plain snapshot), control API
  (`sentinel config`, `sentinel state --json`), systemd/cron scheduling, Markdown/JSON
  run reports, LangGraph orchestration (optional extra).

### Project
- Project renamed **BOGYO** (formerly Sentinel-Guard). The Python package and the
  `sentinel` command keep their names; `bogyo` is added as an alias command.
- Ink, off-white and crimson visual identity (README banner, social preview, TUI theme).
- Fixed: the TUI crashed on its pipeline timer with current Textual releases.
- English documentation: whitepaper, mesh setup, publication set (concept &
  architecture, usage guide, paper draft, safe-use requests, disclaimer).
- CI on Python 3.11–3.13, including a check that no secrets or local state are tracked.

[0.1.0]: https://github.com/Hirasawakazumaz/sentinel-guard/releases/tag/v0.1.0
