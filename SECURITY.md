# Security Policy

## Reporting a vulnerability
Please report security issues privately via a GitHub Security Advisory (or the contact
in the repository) rather than a public issue. Include reproduction steps and affected
versions. We aim to acknowledge within a few days.

## Scope of this project's safeguards
Sentinel-Guard is designed to **fail closed**. The following are treated as security
bugs and are covered by the test suite in `tests/`:
- Authorizing an action against a target outside the signed scope.
- Permitting red-team/exploit validation against production or outside a sandbox.
- Running any active capability with its toggle off or while `dry_run` is implied off
  without explicit configuration.
- Accepting an unsigned/invalid scope or consent, or a tampered audit log.
- Any code path that performs an active operation without first obtaining a
  `ScopeGuard.authorize(...)` decision.

If you find a way to bypass the guard, that is a high-severity report.

## Responsible use
This tool must only be pointed at assets you own or are authorized to test. See
[TERMS_OF_USE.md](TERMS_OF_USE.md) and [docs/legal.md](docs/legal.md).
