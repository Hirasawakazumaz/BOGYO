"""`sentinel` CLI — operator interface with consent and safety gating.

Subcommands:
  init         create config/ + state/, generate the consent keypair
  keygen       generate the scope signing keypair (scope.key / scope.pub)
  sign-scope   sign config/scope.yaml -> config/scope.yaml.sig
  consent      run the interactive consent flow -> config/consent.signed
  status       show mode, toggles, scope hash, consent & audit integrity
  verify       verify scope signature, consent, and audit-log chain
  block        detect attacker IPs from a log file and block them (dry-run default)
  scan         run an active scan against an in-scope host (dry-run default)
  sandbox      replay a finding in an isolated Docker sandbox (redteam, sandbox-only)
  patch        propose config hardening (unified diff); apply needs toggle + approval
  schedule     emit systemd timer + cron for periodic defensive runs (dry-run prints them)
  report       build a Markdown/JSON run report from the audit log
  dashboard    cyber world-map defense dashboard (TUI; --once prints a snapshot)
  usage        show the Claude usage governor (budget/model/throttle) state
  kill/resume  engage or release the kill-switch
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import json as _json

from .. import __version__
from .. import control
from ..i18n import LANGUAGES, normalize_lang, t
from ..block import FirewallBlocker
from ..core import killswitch
from ..core.audit import AuditLog
from ..core.config import Settings, load_verified_scope
from ..core.consent import (
    ACCEPT_PHRASE,
    REQUIRED_CLAUSES,
    ensure_consent_keypair,
    verify_consent,
    write_consent,
)
from ..core.errors import SentinelError
from ..core.signing import generate_keypair, load_private_key, sign
from ..guards import ScopeGuard
from ..intake import detect_bruteforce_ips
from ..patch import Finding, PatchProposer, apply_to_host, default_backend
from ..report import ReportBuilder
from ..sandbox import SandboxReplay
from ..scan import Scanner
from ..schedule import generate as generate_schedule
from ..dashboard import DashboardModel, render_snapshot, run_app
from ..usage.governor import Governor
from ..usage.ledger import UsageLedger

DEFAULT_SETTINGS = "config/settings.yaml"


def _load_settings(path: str) -> Settings:
    return Settings.load(path)


def _print(msg: str) -> None:
    print(msg, flush=True)


_LANG = "en"


def _detect_lang(settings_path: str) -> str:
    try:
        return Settings.load(settings_path).ui.language
    except Exception:  # noqa: BLE001 - language is best-effort
        return "en"


def tr(key: str, **kw) -> str:
    s = t(key, _LANG)
    return s.format(**kw) if kw else s


# --------------------------------------------------------------------------- #
# subcommands
# --------------------------------------------------------------------------- #
def cmd_init(args) -> int:
    Path("config").mkdir(exist_ok=True)
    Path("state").mkdir(exist_ok=True)
    ensure_consent_keypair("config/consent.key", "config/consent.pub")

    # Language selection (first thing at install): --lang, else prompt, else en.
    lang = args.lang
    if not lang:
        try:
            lang = input("Choose language / 言語を選択 [en/ja] (en): ").strip()
        except EOFError:
            lang = "en"
    lang = normalize_lang(lang or "en")
    global _LANG
    _LANG = lang

    # Scaffold / update settings.yaml with the chosen language (keeps existing values).
    settings_path = Path(args.settings)
    settings = Settings.load(settings_path) if settings_path.exists() else Settings()
    settings.ui.language = lang
    settings.save(settings_path)

    _print(tr("cli.init.welcome"))
    _print(tr("cli.init.done", lang=lang))
    _print(tr("cli.init.next", path=str(settings_path)))
    return 0


def cmd_keygen(args) -> int:
    generate_keypair(Path("config/scope.key"), Path("config/scope.pub"))
    _print(tr("cli.keygen.done"))
    return 0


def cmd_sign_scope(args) -> int:
    import yaml

    from ..core.config import ScopeDoc

    data = yaml.safe_load(Path(args.scope).read_text(encoding="utf-8")) or {}
    scope = ScopeDoc.model_validate(data)
    priv = load_private_key(Path(args.key))
    sig = sign(priv, scope.canonical())
    Path(args.scope + ".sig").write_bytes(sig)
    _print(tr("cli.signscope.done", scope=args.scope, h=scope.scope_hash()[:16]))
    return 0


def cmd_consent(args) -> int:
    settings = _load_settings(args.settings)
    scope = load_verified_scope(
        settings.paths.scope_file, settings.paths.scope_sig_file, settings.paths.scope_pubkey_file
    )
    ensure_consent_keypair(settings.paths.consent_file.replace(".signed", ".key"), settings.paths.consent_pubkey_file)
    priv_key = settings.paths.consent_file.replace(".signed", ".key")

    _print(tr("cli.consent.title"))
    _print(tr("cli.consent.intro"))
    _print(tr("cli.consent.owner", name=scope.owner_name, org=scope.owner_org))
    _print(tr("cli.consent.hash", h=scope.scope_hash()))
    _print(tr("cli.consent.accept_all") + "\n")
    for cid, text in REQUIRED_CLAUSES.items():
        _print(f"  [{cid}] {text}\n")

    if args.yes:
        name = args.operator_name or scope.owner_name
        org = args.operator_org or scope.owner_org
        accepted = list(REQUIRED_CLAUSES.keys())
        phrase = ACCEPT_PHRASE
    else:
        name = input(tr("cli.consent.prompt_name")).strip()
        org = input(tr("cli.consent.prompt_org")).strip()
        accepted = []
        for cid in REQUIRED_CLAUSES:
            ans = input(tr("cli.consent.prompt_clause", cid=cid)).strip().lower()
            if ans == "yes":
                accepted.append(cid)
        _print("\n" + tr("cli.consent.type_phrase", phrase=ACCEPT_PHRASE))
        phrase = input("> ").strip()

    record = write_consent(
        scope=scope,
        operator_name=name,
        operator_org=org,
        accepted_clauses=accepted,
        accept_phrase=phrase,
        private_key_path=priv_key,
        out_path=settings.paths.consent_file,
    )
    _print("\n" + tr("cli.consent.saved", path=settings.paths.consent_file, h=record.scope_hash[:16]))
    return 0


def cmd_status(args) -> int:
    settings = _load_settings(args.settings)
    _print(tr("cli.status.header", ver=__version__))
    _print(tr("cli.status.dry_run", v=settings.dry_run))
    _print(tr("cli.status.toggles", v=settings.toggles.model_dump()))
    _print(tr("cli.status.limits", v=settings.limits.model_dump()))
    try:
        scope = load_verified_scope(
            settings.paths.scope_file, settings.paths.scope_sig_file, settings.paths.scope_pubkey_file
        )
        _print(tr("cli.status.scope_ok", h=scope.scope_hash()[:16],
                  hosts=len(scope.allowed_hosts), cidrs=len(scope.allowed_cidrs)))
        try:
            verify_consent(settings.paths.consent_file, settings.paths.consent_pubkey_file, scope.scope_hash())
            _print(tr("cli.status.consent_ok"))
        except SentinelError as exc:
            _print(tr("cli.status.consent_bad", msg=exc))
    except SentinelError as exc:
        _print(tr("cli.status.scope_bad", msg=exc))
    audit = AuditLog(settings.paths.audit_file)
    state = tr("status.intact") if audit.verify_chain() else tr("status.tampered")
    _print(tr("cli.status.audit", state=state, path=settings.paths.audit_file))
    killed = Path(settings.paths.killswitch_file).exists()
    _print(tr("cli.status.kill_engaged" if killed else "cli.status.kill_clear"))
    return 0


def cmd_verify(args) -> int:
    settings = _load_settings(args.settings)
    scope = load_verified_scope(
        settings.paths.scope_file, settings.paths.scope_sig_file, settings.paths.scope_pubkey_file
    )
    verify_consent(settings.paths.consent_file, settings.paths.consent_pubkey_file, scope.scope_hash())
    ok = AuditLog(settings.paths.audit_file).verify_chain()
    if not ok:
        _print(tr("cli.verify.tampered"))
        return 2
    _print(tr("cli.verify.ok"))
    return 0


def cmd_block(args) -> int:
    settings = _load_settings(args.settings)
    guard = ScopeGuard.from_settings(settings)
    blocker = FirewallBlocker(guard)
    lines = Path(args.from_logs).read_text(encoding="utf-8", errors="replace").splitlines()
    signals = detect_bruteforce_ips(lines, threshold=args.threshold)
    if not signals:
        _print(tr("cli.block.none"))
        return 0
    for sig in signals:
        result = blocker.block_ip(sig.ip, ttl_seconds=args.ttl)
        mode = tr("cli.dry") if result.dry_run else tr("cli.applied")
        _print(tr("cli.block.line", mode=mode, ip=sig.ip, count=sig.count, cmd=result.command))
    return 0


def cmd_scan(args) -> int:
    settings = _load_settings(args.settings)
    guard = ScopeGuard.from_settings(settings)
    plan = Scanner(guard).scan(args.target, tool=args.tool)
    mode = tr("cli.dry") if plan.dry_run else tr("cli.scan.rc", rc=plan.returncode)
    _print(tr("cli.scan.line", mode=mode, tool=plan.tool, target=plan.target, cmd=" ".join(plan.command)))
    if plan.output:
        _print(plan.output)
    return 0


def _parse_validations(items) -> list:
    import shlex

    out = []
    for raw in items or []:
        if "=" not in raw:
            raise ValueError(f"--validate must be name=command, got {raw!r}")
        name, cmd = raw.split("=", 1)
        out.append((name.strip(), shlex.split(cmd)))
    return out


def cmd_sandbox(args) -> int:
    settings = _load_settings(args.settings)
    guard = ScopeGuard.from_settings(settings)
    sb = SandboxReplay(guard, replica=args.replica, compose_file=args.compose)
    validations = _parse_validations(args.validate)
    plan = sb.replay(validations)
    mode = "DRY-RUN" if plan.dry_run else "EXECUTED"
    _print(f"[{mode}] sandbox replica={plan.replica} network={plan.network}")
    for c in plan.up_commands:
        _print(f"  up:   {c}")
    for v in plan.validations:
        status = "planned" if v.dry_run else ("BREACH" if v.breached else "clean")
        _print(f"  val:  {v.name} [{status}] {' '.join(v.command)}")
    for c in plan.down_commands:
        _print(f"  down: {c}")
    return 0


def cmd_patch(args) -> int:
    settings = _load_settings(args.settings)
    guard = ScopeGuard.from_settings(settings)
    original = Path(args.config).read_text(encoding="utf-8") if Path(args.config).exists() else ""
    finding = Finding(
        id=args.finding_id,
        target=args.host or "",
        service=args.service,
        title=args.title or f"harden {args.service}",
        path=args.config,
        original=original,
    )
    gov = Governor(settings.usage, UsageLedger(settings.paths.usage_file))
    candidates = PatchProposer(guard, default_backend(governor=gov, settings=settings)).propose(finding)
    if not candidates:
        _print(f"no hardening candidate for service {args.service!r} / {args.config}")
        return 0
    for c in candidates:
        _print(f"# candidate for {c.service} ({c.path}): {c.rationale}")
        _print(c.unified_diff() or "(no textual diff)")
        if args.apply:
            if not args.host:
                _print("ERROR: --apply requires --host")
                return 1
            res = apply_to_host(guard, c, host=args.host, approved=args.approve)
            mode = "DRY-RUN (not written)" if res.dry_run else "APPLIED"
            _print(f"[{mode}] -> {args.host}:{c.path}")
    return 0


def cmd_schedule(args) -> int:
    unit = generate_schedule(
        args.command,
        name=args.name,
        on_calendar=args.on_calendar,
        user=args.user,
        working_directory=args.workdir,
    )
    _print("# DRY-RUN: review and install these as root (systemctl daemon-reload, enable --now)")
    _print(unit.describe())
    return 0


def cmd_report(args) -> int:
    settings = _load_settings(args.settings)
    report = ReportBuilder(settings.paths.audit_file).write(args.md, args.json)
    _print(report.to_markdown())
    if args.md:
        _print(f"\n(markdown written to {args.md})")
    if args.json:
        _print(f"(json written to {args.json})")
    return 0


def cmd_dashboard(args) -> int:
    settings = _load_settings(args.settings)
    if args.once:
        _print(render_snapshot(DashboardModel(settings).build()))
        return 0
    run_app(args.settings)  # interactive Textual UI (needs [tui] extra)
    return 0


def cmd_usage(args) -> int:
    settings = _load_settings(args.settings)
    gov = Governor(settings.usage, UsageLedger(settings.paths.usage_file))
    if args.record:
        gov.ledger.record(args.record, model=args.model, op="manual")
    st = gov.state()
    _print(f"provider      : {st.provider}")
    _print(f"tokens today  : {st.tokens_today:,} / {st.budget:,}  {st.bar()} {int(st.fraction*100)}%")
    _print(f"level         : {st.level}")
    _print(f"model (gov)   : {st.model}")
    _print(f"runs/hour     : {st.runs_per_hour}")
    _print(f"run allowed   : {'YES' if st.allow_run else 'NO (budget reached — resumes after reset)'}")
    _print(f"resets at     : {st.resets_at}")
    return 0


def cmd_config(args) -> int:
    settings = _load_settings(args.settings)
    if args.action == "dump":
        _print(_json.dumps(control.dump(settings), ensure_ascii=False, indent=2))
    elif args.action == "get":
        _print(_json.dumps(control.get_value(settings, args.key), ensure_ascii=False, indent=2))
    elif args.action == "set":
        result = control.set_value(settings, args.key, args.value, args.settings)
        _print(_json.dumps(result, ensure_ascii=False))
    return 0


def cmd_state(args) -> int:
    settings = _load_settings(args.settings)
    if args.json:
        _print(_json.dumps(control.state_dict(settings), ensure_ascii=False, indent=2, default=str))
    else:
        _print(render_snapshot(DashboardModel(settings).build()))
    return 0


def cmd_mesh(args) -> int:
    import getpass

    from ..mesh import NodeIdentity, PatchChain, node_from_settings, push as mesh_push, serve as mesh_serve

    settings = _load_settings(args.settings)
    mc = settings.mesh

    def _pw() -> str:
        return args.passphrase or getpass.getpass("node key passphrase: ")

    if args.action == "keygen":
        name = args.name or mc.node_name or "node"
        idn = NodeIdentity.create(name)
        idn.save(mc.key_file, _pw())
        _print(f"node '{name}' key saved (machine-bound): {mc.key_file}")
        _print(f"  ed25519_pub: {idn.ed25519_pub_hex()}")
        _print(f"  x25519_pub : {idn.x25519_pub_hex()}")
        _print("share these PUBLIC keys with your other servers' mesh config (peers).")
        return 0

    if args.action == "status":
        _print(f"mesh enabled: {mc.enabled}  node: {mc.node_name or '-'}  domain: {mc.domain or '-'}")
        _print(f"peers configured: {len(mc.peers)}")
        for p in mc.peers:
            _print(f"  - {p.name}  domain={p.domain or '-'}  endpoint={p.endpoint or '-'}")
        chain = PatchChain(mc.chain_file)
        _print(f"patch chain height: {chain.height()}  pending: {len(chain.pending())}  "
               f"applied: {len(chain.applied())}  valid: {chain.validate()}")
        return 0

    if args.action == "propose":
        node = node_from_settings(settings, _pw())
        block = node.propose({"service": args.service or mc.domain or "generic",
                              "finding": args.finding or "F-manual",
                              "path": args.path or "", "note": args.note or ""})
        _print(f"proposed block #{block.index} ({block.domain}) hash={block.hash[:16]}… status=shared")
        return 0

    if args.action == "serve":
        from ..mesh import ConflictGate
        from ..patch import ConflictEvaluator

        # Peers' patches are applied only through the guarded sandbox conflict-eval.
        guard = ScopeGuard.from_settings(settings)
        sandbox = None
        if args.replica:
            if not guard.scope.contains(args.replica) or guard.scope.is_production(args.replica):
                _print(f"ERROR: --replica {args.replica!r} must be an in-scope, non-production host")
                return 1
            sandbox = SandboxReplay(guard, replica=args.replica, compose_file=args.compose)
        checks = _parse_validations(args.check) or None
        gate = ConflictGate(ConflictEvaluator(guard, sandbox=sandbox), checks)
        node = node_from_settings(settings, _pw())
        _print(f"mesh node '{node.identity.name}' (domain={node.domain}) serving on {args.host}:{args.port}")
        _print(f"peers: {', '.join(p.name for p in mc.peers) or '(none)'}  — Ctrl-C to stop")
        mode = "DRY-RUN (peers' patches stay shared)" if settings.dry_run else "LIVE sandbox checks"
        _print(f"conflict gate: {mode}; replica={args.replica or '-'} checks={len(checks or [])}")
        mesh_serve(node, args.host, args.port, checker=gate)  # blocking
        return 0

    if args.action == "push":
        node = node_from_settings(settings, _pw())
        peer = next((p for p in mc.peers if p.name == args.to), None)
        if peer is None:
            _print(f"ERROR: peer '{args.to}' not in mesh.peers")
            return 1
        endpoint = args.endpoint or peer.endpoint
        if not endpoint:
            _print(f"ERROR: no endpoint for peer '{args.to}' (set peers[].endpoint or --endpoint)")
            return 1
        blocks = node.chain.pending() if args.pending else node.chain.blocks[-1:]
        if not blocks:
            _print("nothing to push (chain empty); run `sentinel mesh propose` first")
            return 0
        acks = mesh_push(node, args.to, endpoint, blocks)
        for a in acks:
            reason = f"  ({a['reason']})" if a.get("reason") else ""
            _print(f"  peer ack: {a.get('status')}  ref={str(a.get('ref'))[:16]}{reason}")
        return 0
    return 0


def cmd_kill(args) -> int:
    settings = _load_settings(args.settings)
    killswitch.engage(settings.paths.killswitch_file, reason=args.reason or "manual")
    _print(tr("cli.kill.engaged", path=settings.paths.killswitch_file))
    return 0


def cmd_resume(args) -> int:
    settings = _load_settings(args.settings)
    killswitch.release(settings.paths.killswitch_file)
    _print(tr("cli.kill.released"))
    return 0


# --------------------------------------------------------------------------- #
# parser
# --------------------------------------------------------------------------- #
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="sentinel", description="Authorized proactive defense (own assets only).")
    p.add_argument("--version", action="version", version=f"sentinel-guard {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    def with_settings(sp):
        sp.add_argument("--settings", default=DEFAULT_SETTINGS)
        return sp

    sp = with_settings(sub.add_parser("init", help="scaffold config/state, pick language, make consent keypair"))
    sp.add_argument("--lang", default="", choices=["", *LANGUAGES], help="UI language (en/ja); prompts if omitted")
    sp.set_defaults(func=cmd_init)
    sub.add_parser("keygen").set_defaults(func=cmd_keygen)

    sp = sub.add_parser("sign-scope")
    sp.add_argument("--scope", default="config/scope.yaml")
    sp.add_argument("--key", default="config/scope.key")
    sp.set_defaults(func=cmd_sign_scope)

    sp = with_settings(sub.add_parser("consent"))
    sp.add_argument("--yes", action="store_true", help="non-interactive accept-all (CI/testing)")
    sp.add_argument("--operator-name", default="")
    sp.add_argument("--operator-org", default="")
    sp.set_defaults(func=cmd_consent)

    with_settings(sub.add_parser("status")).set_defaults(func=cmd_status)
    with_settings(sub.add_parser("verify")).set_defaults(func=cmd_verify)

    sp = with_settings(sub.add_parser("block"))
    sp.add_argument("--from-logs", required=True)
    sp.add_argument("--threshold", type=int, default=5)
    sp.add_argument("--ttl", type=int, default=3600)
    sp.set_defaults(func=cmd_block)

    sp = with_settings(sub.add_parser("scan"))
    sp.add_argument("target")
    sp.add_argument("--tool", default="nmap")
    sp.set_defaults(func=cmd_scan)

    sp = with_settings(sub.add_parser("sandbox", help="replay a finding in an isolated Docker sandbox"))
    sp.add_argument("--replica", required=True, help="in-scope, non-production host id the replica reproduces")
    sp.add_argument("--compose", default=None, help="docker compose file for the replica")
    sp.add_argument("--validate", action="append", metavar="NAME=CMD",
                    help="attack-style validation command (repeatable), e.g. nuclei='docker run --rm ...'")
    sp.set_defaults(func=cmd_sandbox)

    sp = with_settings(sub.add_parser("patch", help="propose config hardening (and optionally apply)"))
    sp.add_argument("--service", required=True, help="service to harden (sshd, nginx, postgres, ...)")
    sp.add_argument("--config", required=True, help="path to the current config file to harden")
    sp.add_argument("--finding-id", default="F-cli")
    sp.add_argument("--title", default="")
    sp.add_argument("--host", default="", help="host for --apply (must be in scope)")
    sp.add_argument("--apply", action="store_true", help="apply to --host (needs enable_patch_apply + --approve)")
    sp.add_argument("--approve", action="store_true", help="explicit human approval for --apply")
    sp.set_defaults(func=cmd_patch)

    sp = sub.add_parser("schedule", help="emit systemd timer + cron for periodic defensive runs")
    sp.add_argument("--command", required=True, help="sentinel args to schedule, e.g. 'block --from-logs /var/log/auth.log'")
    sp.add_argument("--name", default="sentinel-guard")
    sp.add_argument("--on-calendar", default="daily")
    sp.add_argument("--user", default="root")
    sp.add_argument("--workdir", default="/opt/sentinel-guard")
    sp.set_defaults(func=cmd_schedule)

    sp = with_settings(sub.add_parser("report", help="build a run report from the audit log"))
    sp.add_argument("--md", default=None, help="also write Markdown to this path")
    sp.add_argument("--json", default=None, help="also write JSON to this path")
    sp.set_defaults(func=cmd_report)

    sp = with_settings(sub.add_parser("dashboard", help="cyber world-map defense dashboard (TUI; --once for a snapshot)"))
    sp.add_argument("--once", action="store_true", help="print one plain-text snapshot and exit (no TUI deps)")
    sp.set_defaults(func=cmd_dashboard)

    sp = with_settings(sub.add_parser("usage", help="show Claude usage governor state; --record adds tokens"))
    sp.add_argument("--record", type=int, default=0, help="record N tokens spent (integration/testing)")
    sp.add_argument("--model", default="", help="model label for --record")
    sp.set_defaults(func=cmd_usage)

    # machine-readable control API (read/change everything from another app)
    sp = with_settings(sub.add_parser("config", help="read/change settings as JSON (control API)"))
    csub = sp.add_subparsers(dest="action", required=True)
    csub.add_parser("dump", help="print full settings as JSON")
    g = csub.add_parser("get", help="print one value as JSON")
    g.add_argument("key", help="dotted key, e.g. usage.daily_token_budget")
    s = csub.add_parser("set", help="set + persist one value (JSON or string)")
    s.add_argument("key")
    s.add_argument("value")
    sp.set_defaults(func=cmd_config)

    sp = with_settings(sub.add_parser("state", help="dashboard state (--json for machine-readable)"))
    sp.add_argument("--json", action="store_true", help="emit the full state as JSON")
    sp.set_defaults(func=cmd_state)

    sp = with_settings(sub.add_parser("mesh", help="distributed patch mesh among YOUR OWN servers"))
    msub = sp.add_subparsers(dest="action", required=True)
    mk = msub.add_parser("keygen", help="create this node's machine-bound encrypted key")
    mk.add_argument("--name", default="")
    mk.add_argument("--passphrase", default="", help="non-interactive passphrase (else prompt)")
    msub.add_parser("status", help="show node, peers, and patch-chain state")
    mpr = msub.add_parser("propose", help="create a signed patch block on the local chain")
    mpr.add_argument("--service", default=""); mpr.add_argument("--finding", default="")
    mpr.add_argument("--path", default=""); mpr.add_argument("--note", default="")
    mpr.add_argument("--passphrase", default="")
    msv = msub.add_parser("serve", help="run this node's mesh endpoint (blocking)")
    msv.add_argument("--host", default="127.0.0.1"); msv.add_argument("--port", type=int, default=8787)
    msv.add_argument("--passphrase", default="")
    msv.add_argument("--replica", default="", help="in-scope, non-production sandbox replica for conflict-eval")
    msv.add_argument("--compose", default=None, help="docker compose file of the replica (default restart check)")
    msv.add_argument("--check", action="append", metavar="NAME=CMD",
                     help="local conflict check run in the sandbox (repeatable); never taken from peers")
    mpu = msub.add_parser("push", help="send patch block(s) to a peer over the rolling-key channel")
    mpu.add_argument("--to", required=True, help="peer name from mesh.peers")
    mpu.add_argument("--endpoint", default="", help="override peer endpoint (http://host:port)")
    mpu.add_argument("--pending", action="store_true", help="push all pending blocks (else the latest)")
    mpu.add_argument("--passphrase", default="")
    sp.set_defaults(func=cmd_mesh)

    sp = with_settings(sub.add_parser("kill"))
    sp.add_argument("--reason", default="")
    sp.set_defaults(func=cmd_kill)

    with_settings(sub.add_parser("resume")).set_defaults(func=cmd_resume)
    return p


def main(argv=None) -> int:
    global _LANG
    args = build_parser().parse_args(argv)
    _LANG = _detect_lang(getattr(args, "settings", DEFAULT_SETTINGS))
    try:
        return args.func(args)
    except SentinelError as exc:
        _print(tr("cli.refused", kind=type(exc).__name__, msg=str(exc)))
        return 2
    except (ValueError, FileNotFoundError, RuntimeError) as exc:
        _print(tr("cli.error", msg=str(exc)))
        return 1


if __name__ == "__main__":
    sys.exit(main())
