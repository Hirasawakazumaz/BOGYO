"""CLI status/block/scan output goes through the string table (English)."""

from __future__ import annotations

from sentinel.cli.main import main

AUTH_LOG = "\n".join(
    f"Jan 1 00:00:0{i} h sshd[1]: Failed password for root from 198.51.100.9 port {i} ssh2"
    for i in range(1, 6)
) + "\n"


def _settings_file(env, tmp_path, lang="en"):
    env.settings.ui.language = lang
    sp = str(tmp_path / "settings.yaml")
    env.settings.save(sp)
    return sp


def test_status_output(make_env, tmp_path, capsys):
    sp = _settings_file(make_env(), tmp_path)
    assert main(["status", "--settings", sp]) == 0
    out = capsys.readouterr().out
    assert "scope  : VERIFIED" in out and "consent: VERIFIED" in out
    assert "audit  : INTACT" in out and "kill   : clear" in out


def test_legacy_language_setting_falls_back_to_english(make_env, tmp_path, capsys):
    sp = _settings_file(make_env(), tmp_path, "ja")
    assert main(["status", "--settings", sp]) == 0
    assert "scope  : VERIFIED" in capsys.readouterr().out


def test_block_dry_run(make_env, tmp_path, capsys):
    sp = _settings_file(make_env(enable_blocking=True), tmp_path)
    log = tmp_path / "auth.log"
    log.write_text(AUTH_LOG, encoding="utf-8")
    assert main(["block", "--settings", sp, "--from-logs", str(log)]) == 0
    assert "[DRY-RUN] 198.51.100.9 (x5) ->" in capsys.readouterr().out


def test_block_none(make_env, tmp_path, capsys):
    sp = _settings_file(make_env(enable_blocking=True), tmp_path)
    log = tmp_path / "auth.log"
    log.write_text("nothing here\n", encoding="utf-8")
    assert main(["block", "--settings", sp, "--from-logs", str(log)]) == 0
    assert "No offending IPs met the threshold." in capsys.readouterr().out


def test_scan_dry_run(make_env, tmp_path, capsys):
    sp = _settings_file(make_env(enable_active_scan=True), tmp_path)
    assert main(["scan", "--settings", sp, "10.0.0.5"]) == 0
    assert "[DRY-RUN] nmap 10.0.0.5: nmap -sV" in capsys.readouterr().out


def test_scan_out_of_scope_refused(make_env, tmp_path, capsys):
    sp = _settings_file(make_env(enable_active_scan=True), tmp_path)
    assert main(["scan", "--settings", sp, "192.0.2.77"]) == 2
    assert "REFUSED (" in capsys.readouterr().out
