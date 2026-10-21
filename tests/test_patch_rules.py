"""RuleBackend hardening rules: coverage, placement, idempotency, never-weaken."""

from __future__ import annotations

from sentinel.patch import Finding, RuleBackend

SSHD_UBUNTU = """\
Include /etc/ssh/sshd_config.d/*.conf

#LoginGraceTime 2m
#PermitRootLogin prohibit-password
#MaxAuthTries 6

# To disable tunneled clear text passwords, change to no here!
PasswordAuthentication yes
#PermitEmptyPasswords no

# PasswordAuthentication.  Depending on your PAM configuration,
KbdInteractiveAuthentication yes
X11Forwarding yes

Match User backup
\tPasswordAuthentication yes
"""


def _f(service: str, original: str, path: str = "/etc/x.conf") -> Finding:
    return Finding(id="F-r", target="10.0.0.5", service=service, title="harden",
                   path=path, original=original)


def _harden(service: str, original: str) -> str:
    cands = RuleBackend().propose(_f(service, original))
    assert len(cands) == 1
    return cands[0].hardened


def test_sshd_rules_replace_insert_and_keep_prose():
    out = _harden("sshd", SSHD_UBUNTU)
    lines = out.splitlines()
    for directive in ("PermitRootLogin no", "PasswordAuthentication no", "PermitEmptyPasswords no",
                      "KbdInteractiveAuthentication no", "X11Forwarding no", "MaxAuthTries 3",
                      "LoginGraceTime 30", "HostbasedAuthentication no", "IgnoreRhosts yes",
                      "PermitUserEnvironment no", "ChallengeResponseAuthentication no"):
        assert directive in lines, directive
    # explanatory comment prose is not turned into a directive
    assert "# PasswordAuthentication.  Depending on your PAM configuration," in lines
    # inserted directives land before Match (so they apply globally)
    match_at = lines.index("Match User backup")
    assert lines.index("HostbasedAuthentication no") < match_at
    # the Match block entry is tightened with its indentation kept
    assert lines[match_at + 1] == "\tPasswordAuthentication no"
    assert "PasswordAuthentication yes" not in out


def test_rules_are_idempotent():
    for service, original in (("sshd", SSHD_UBUNTU), ("sysctl", "")):
        once = _harden(service, original)
        assert RuleBackend().propose(_f(service, once)) == []


def test_nginx_tightens_and_inserts_into_http_block():
    conf = (
        "http {\n"
        "    ssl_protocols TLSv1 TLSv1.1 TLSv1.2;\n"
        "    server {\n"
        "        autoindex on;\n"
        "    }\n"
        "}\n"
    )
    out = _harden("nginx", conf)
    assert out.startswith("http {\n    server_tokens off;\n")
    assert "    ssl_protocols TLSv1.2 TLSv1.3;" in out
    assert "        autoindex off;" in out


def test_nginx_never_weakens_and_needs_http_context_to_insert():
    # TLSv1.3-only must not be rewritten to allow TLSv1.2; existing server_tokens off kept
    strict = "http {\n    server_tokens off;\n    ssl_protocols TLSv1.3;\n}\n"
    assert RuleBackend().propose(_f("nginx", strict)) == []
    # a bare server snippet has no safe spot for an http-level directive
    site = "server {\n    listen 80;\n}\n"
    assert RuleBackend().propose(_f("nginx", site)) == []


def test_postgres_rules():
    conf = "#ssl = off\npassword_encryption = md5\t# legacy\n#log_connections = off\n"
    out = _harden("postgresql", conf)  # alias
    lines = out.splitlines()
    assert lines[:3] == ["ssl = on", "password_encryption = scram-sha-256", "log_connections = on"]
    assert "log_disconnections = on" in lines
    # scram is never downgraded
    assert "scram-sha-256" in _harden("postgres", "password_encryption = scram-sha-256\n")


def test_sysctl_uncomments_and_appends_without_trailing_newline():
    conf = "#net.ipv4.conf.all.accept_redirects = 1\nkernel.randomize_va_space=0"
    out = _harden("sysctl", conf)
    lines = out.splitlines()
    assert lines[0] == "net.ipv4.conf.all.accept_redirects = 0"
    assert lines[1] == "kernel.randomize_va_space = 2"
    assert "net.ipv4.tcp_syncookies = 1" in lines and out.endswith("\n")


def test_refine_keeps_only_top_rule_and_unknown_service_is_noop():
    be = RuleBackend()
    finding = _f("openssh", SSHD_UBUNTU)
    full = be.propose(finding)[0]
    refined = be.refine(finding, full, ["startup:restart"])
    assert len(refined) == 1 and refined[0].changes == ["disable direct root SSH login"]
    assert be.propose(_f("unknown-svc", "x = 1\n")) == []
