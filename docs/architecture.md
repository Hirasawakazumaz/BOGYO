# Architecture

```
            config/scope.yaml (+ .sig)        config/consent.signed
            config/settings.yaml                      |
                       \                               /
                        \                             /
                   ScopeGuard.from_settings()  --- fail closed if any check fails
                   (verify scope sig, verify consent vs scope hash,
                    check kill-switch, open hash-chained audit log)
                                   |
                                   v
             +----------------- ScopeGuard.authorize(action, target, ...) ----------------+
             | PASSIVE_READ | ACTIVE_SCAN | REDTEAM_ATTACK | BLOCK | PATCH_PROPOSE | APPLY |
             +--------------------------------------------------------------------------- +
                                   |  (every call audited: allow/deny)
         +-------------+-----------+-----------+--------------+---------------+
         v             v           v           v              v               v
     intake/       scan/       sandbox/     block/         patch/          schedule/
   logwatch,     scanner,    replay        nftables      propose +        systemd timer
   threatintel   cve         (Docker,      drop rules    conflict eval    + cron
                             isolated)      no hack-back  (sandbox loop)

                         graph/ SentinelPipeline ties the above together
                         report/ tallies everything from the audit log
```

## Layers

- **core/** — safety primitives, loaded before anything else: `config` (settings +
  signed scope), `signing` (Ed25519 + canonical hashing), `consent`, `audit`
  (append-only hash chain), `killswitch`, `actions` (ActionClass), `errors`.
- **guards/** — `ScopeGuard`, the single authorization path. No bypass exists.
- **intake/** — pure, offline log analysis -> attacker IPs.
- **block/** — defensive nftables blocking with TTL; dry-run builds the command only.
- **scan/** — orchestration of nmap/nuclei (active) and OSV CVE lookup (passive).
- **sandbox/** — `SandboxReplay`: ephemeral, network-isolated (`--internal`) Docker
  Compose replica of an in-scope service. Attack-style validation routes through
  `REDTEAM_ATTACK` + `environment="sandbox"` (hard-refused on production and when the
  toggle is off). Isolation is enforced structurally, fail-closed, even in dry-run:
  - the **compose file is parsed as YAML** (not string-matched) and refused unless
    every service attaches only to `internal: true` networks (never the default
    bridge) and opens no escape hatch — `privileged`, host namespaces
    (`network_mode`/`pid`/`ipc`/`uts`/`userns_mode: host`), `cap_add`, `devices`,
    unconfined `security_opt`, a docker-socket / host-path bind, or published `ports`;
  - each **validation command must be bound to the sandbox** (its network or compose
    project), and a `docker run`/`create` must use `--network <internal net>`, so a
    validation can never target an arbitrary host;
  - raw commands are also scanned for `--privileged`, `--net=host` /
    `--network host`, `--cap-add`, and docker-socket binds.

  dry-run returns commands; bring-up, each validation, and teardown are all audited
  and teardown always runs.
- **patch/** — `PatchProposer` generates config-hardening candidates
  (`PATCH_PROPOSE`) via a clean `PatchBackend` interface: a deterministic offline
  `RuleBackend` (default, keeps core testable) and a lazy `AnthropicBackend` that
  falls back to rules. `ConflictEvaluator` + `PatchLoop` apply candidates in the
  sandbox and iterate propose→evaluate→refine, checking startup/dependency/perf.
  Candidates emit unified diffs. `apply_to_host` is the only host-mutating path —
  `PATCH_APPLY` + `enable_patch_apply` + explicit `approved=True`, never in dry-run.
- **graph/** — `SentinelPipeline` runs the guarded nodes intake→scan→sandbox→patch
  propose→conflict eval→report in order (every node calls the guard first; a refused
  capability is skipped, never forced). `build_langgraph` wires the same nodes into a
  real `langgraph.StateGraph`; langgraph/anthropic are imported lazily so the core
  works offline without the `agent` extra.
- **schedule/** — emit a hardened systemd service+timer and a cron fallback for
  periodic **defensive** runs; red-team/sandbox subcommands are refused (opt-in,
  sandbox-only, never scheduled).
- **report/** — Markdown+JSON run reports (breach tally, authorizations, applied
  changes, analysis) built purely from the hash-chained audit log; a broken chain is
  flagged.
- **cli/** — operator commands (init, keygen, sign-scope, consent, status, verify,
  block, scan, sandbox, patch, schedule, report, kill/resume).

## Execution modes
- `dry_run: true` (default) — active operations return the exact command/plan and are
  never executed.
- Per-capability toggles gate whether an operation is even authorized.
- Red-team attack validation additionally requires `environment=sandbox` and a
  non-production target; it is hard-refused otherwise.
