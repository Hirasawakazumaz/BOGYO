# Sentinel-Guard

**Authorized, consent-gated proactive defense & self-pentest orchestration for Linux servers.**

Sentinel-Guard helps you find and fix vulnerabilities on **your own** servers *before*
attackers do. It auto-blocks attacking source IPs, runs scheduled diagnostics of the
assets you own, reproduces findings in **isolated Docker sandboxes**, proposes patches,
checks them for service/operational conflicts, and reports — all behind a single
authorization gate that **fails closed**.

> ⚠️ **This tool is for assets you own or are explicitly authorized to test.**
> It will refuse any target outside your signed ownership scope. It never attacks
> third parties and never "hacks back". See [TERMS_OF_USE.md](TERMS_OF_USE.md) and
> [docs/legal.md](docs/legal.md).

## Safety model (why this is safe to run and to publish)

Every active capability routes through `sentinel.guards.ScopeGuard`. Before anything runs:

1. **Signed ownership scope** — you list the hosts/CIDRs you own in `config/scope.yaml`
   and sign it (Ed25519). Any target outside it is refused. Editing the file breaks the
   signature until re-signed.
2. **Operator consent** — you sign a consent record bound to the scope hash. Changing
   the scope forces re-consent. (`sentinel consent`)
3. **Default-deny** — every active capability (`blocking`, `active_scan`,
   `sandbox_redteam`, `patch_apply`) is **off** by default, and `dry_run` is **on**.
4. **Sandbox-only attacks** — red-team/exploit *validation* is permitted only against an
   isolated replica (`environment=sandbox`) and is **hard-refused** on production.
5. **No hack-back** — defense is limited to dropping inbound traffic (`nftables`).
6. **Tamper-evident audit log** — every allow/deny and every action is written to a
   hash-chained log; tampering is detectable (`sentinel verify`).
7. **Kill-switch** — a single file stops everything (`sentinel kill`).

There is intentionally no flag or env var that disables the guard.

## Install (Linux)

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"        # add ".[agent]" for the LangGraph/LLM orchestration
```

## Quick start

```bash
sentinel init                              # create config/ + state/, consent keypair
cp config/scope.example.yaml config/scope.yaml
cp config/settings.example.yaml config/settings.yaml
# edit config/scope.yaml to list ONLY assets you own
sentinel keygen                            # scope signing keypair
sentinel sign-scope                        # sign scope.yaml
sentinel consent                           # accept clauses, sign consent
sentinel status                            # review mode/toggles/scope/consent/audit

# defensive blocking from a log file (dry-run until you enable it in settings):
sentinel block --from-logs /var/log/auth.log --threshold 5

# active scan of an in-scope host (needs toggles.enable_active_scan=true to really run):
sentinel scan 203.0.113.10 --tool nmap
```

Enable real actions only after reviewing dry-run output: set `dry_run: false` and the
relevant toggle in `config/settings.yaml`.

```bash
# reproduce a finding in an isolated Docker sandbox (needs enable_sandbox_redteam;
# sandbox-only, hard-refused on production):
sentinel sandbox --replica 10.0.0.5 --compose docker/sandbox.example.compose.yaml \
  --validate "nuclei=docker run --rm --network sentinel_sbx_10_0_0_5 projectdiscovery/nuclei -u http://web"

# propose config hardening as a unified diff (apply needs enable_patch_apply + --approve):
sentinel patch --service sshd --config /etc/ssh/sshd_config

# emit a systemd timer + cron fallback for a periodic defensive run (prints, never installs):
sentinel schedule --command "block --from-logs /var/log/auth.log" --on-calendar daily

# build a run report from the audit log:
sentinel report --md run.md --json run.json
```

## Status

Implemented: safety core (scope/consent/audit/kill-switch/guard), defensive IP blocking,
scan orchestration, passive CVE lookup, **Docker sandbox replay**, **patch generation +
sandbox conflict-evaluation loop**, **LangGraph orchestration** (lazy; offline-safe),
**systemd/cron scheduling**, **audit-log run reports**, CLI, and test suite.

The LangGraph brain and LLM patch generation need the optional extra
(`pip install -e ".[agent]"`); everything else, including the full pipeline in dry-run,
runs without it.

## Out of scope (by design)

No hack-back, no attacks on systems you don't control, no new exploit development, no
generic attack payloads, no detection-evasion. These are excluded to stay on the safe
side of applicable law.
