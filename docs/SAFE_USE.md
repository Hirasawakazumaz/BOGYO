# Safe-Use Request

This project is shared in the hope it helps people defend **their own** systems.
Please use it in that spirit.

## Please DO
- Use it only on hosts and networks **you own or are explicitly authorized (in
  writing) to test**, declared in your signed scope.
- Keep `dry_run` on and capabilities off until you have reviewed what each does.
- Keep real action (blocking, patch apply, attack validation) behind human review.
- For the server mesh, connect **only your own servers** running this software.
- Keep your private keys (`config/*.key`, node key) secret and backed up safely.

## Please DO NOT
- Do not point it at anyone else's systems, or "hack back" an attacker.
- Do not run attack validation against production — use an isolated sandbox.
- Do not remove, disable, or circumvent the safeguards, or redistribute a build
  with them weakened.

## If in doubt
Stop and ask a qualified security professional and, where relevant, a lawyer. The
defaults are conservative on purpose; keep them that way unless you are sure.

See [../TERMS_OF_USE.md](../TERMS_OF_USE.md), [../DISCLAIMER.md](../DISCLAIMER.md),
and [legal.md](legal.md).
