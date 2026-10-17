# Threat model

## What we protect against
1. **Operator misdirecting the tool at systems they don't own** (accident or coercion).
   - Mitigation: signed scope; every active target checked for scope membership;
     fail closed on out-of-scope.
2. **Scope/consent/audit tampering** to widen authority silently.
   - Mitigation: Ed25519 signatures over canonical bytes; consent bound to scope hash;
     hash-chained audit; all verified at startup and recorded.
3. **Accidental attack on production.**
   - Mitigation: red-team hard-refused on production and off-sandbox; default-deny
     toggles; dry-run default.
4. **A forked/redistributed build with safeguards removed.**
   - Mitigation: single guard path (no disable flag); TERMS forbid safeguard removal;
     safeguards covered by tests so a weakening change fails CI.
5. **Runaway automation** (scheduled runs, rate storms).
   - Mitigation: rate/target/concurrency limits, optional time window, kill-switch.

## Explicit non-goals (not defended, because not built)
- Attacking or hacking back third parties (illegal; excluded by design).
- Novel exploit development or generic weaponized payloads.
- Detection evasion.

## Trust assumptions
- The operator's private keys (`config/*.key`) are kept secret and git-ignored.
- The host OS and the Docker daemon used for sandbox replicas are trusted.
- Threat-intel API keys are provided via environment variables, never committed.
