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
   logwatch,     scanner,    (replay —     nftables      (propose +       (systemd —
   threatintel   cve         later)        drop rules    conflict eval    later)
                                           no hack-back)  — later)
```

## Layers

- **core/** — safety primitives, loaded before anything else: `config` (settings +
  signed scope), `signing` (Ed25519 + canonical hashing), `consent`, `audit`
  (append-only hash chain), `killswitch`, `actions` (ActionClass), `errors`.
- **guards/** — `ScopeGuard`, the single authorization path. No bypass exists.
- **intake/** — pure, offline log analysis -> attacker IPs.
- **block/** — defensive nftables blocking with TTL; dry-run builds the command only.
- **scan/** — orchestration of nmap/nuclei (active) and OSV CVE lookup (passive).
- **cli/** — operator commands (init, keygen, sign-scope, consent, status, verify,
  block, scan, kill/resume).
- **graph/ sandbox/ patch/ schedule/ report/** — approved later phases; each must
  route active work through the guard.

## Execution modes
- `dry_run: true` (default) — active operations return the exact command/plan and are
  never executed.
- Per-capability toggles gate whether an operation is even authorized.
- Red-team attack validation additionally requires `environment=sandbox` and a
  non-production target; it is hard-refused otherwise.
