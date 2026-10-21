# Requests for Safe Use

Sentinel-Guard is a tool for **protecting your own assets before attackers reach them**.
The same techniques become an attack on someone else if pointed at the wrong target. The author does not want this tool used for attacks.
We ask everyone who uses, modifies, redistributes or studies it to follow the requests below.

> This document collects requests and prohibitions. The legal conditions in the [Terms of Use](../../TERMS_OF_USE.md) and the [Disclaimer](05_disclaimer.md) take precedence.

---

## 1. To users

### 1.1 Mandatory (prohibited actions)

- 🚫 **Do not use it on any system you do not own or do not have explicit written authorization to test.**
  "It is publicly reachable", "it looks vulnerable" or "I mean well" is not authorization.
- 🚫 **Do not retaliate against attackers (hack back).** The source of an attack is often an uninvolved person's compromised PC.
- 🚫 **Do not run attack-technique validation on production.** Always use an isolated replica.
- 🚫 **Do not remove or circumvent the safeguards** (guard, signed scope, consent, audit log, kill-switch, isolation checks).
- 🚫 **Do not distribute modified versions with weakened safeguards.**
- 🚫 **Do not use the tool's output (scan results, validation results, etc.) to look for weaknesses in other people's systems.**

### 1.2 Strongly recommended

1. **Start in dry-run.** Keep the default `dry_run: true` for a few days and review the planned actions it shows.
2. **Enable one capability at a time.** Proceed in stages: blocking → scanning → sandbox → apply.
3. **Keep the scope minimal.** List only the assets you need, not "a bit more just in case".
4. **Always put production in `production_hosts`.** Attack validation on production is then refused automatically.
5. **Check your cloud/VPS provider's terms.** Even for servers you rent, providers may restrict penetration testing.
6. **Get written authorization for employer or customer assets**, stating scope, period, methods and contacts.
7. **Keep a separate management path.** Before enabling blocking, confirm you can log in another way (e.g. a console).
8. **Back up before applying.** Save configuration files before applying a fix (the current version makes no automatic backup).
9. **Protect your private keys.** Never share or commit `config/*.key`. If one leaks, regenerate keys, re-sign and re-consent.
10. **Review the audit log regularly.** Make `sentinel verify` and `sentinel report` a habit.
11. **Preserve evidence of tampering.** If you see `audit chain TAMPERED`, do not delete the log; suspect an intrusion and investigate.
12. **Do not trust AI proposals blindly.** Fix proposals can be wrong. Read the diff before approving.
13. **When in doubt, stop.** `sentinel kill` is always available.

### 1.3 Things worth checking in dry-run

- [ ] Every target shown is one of your own assets
- [ ] The IPs to be blocked do not include yours, your family's, your workplace's or your monitoring services'
- [ ] Scan times and frequency will not overload your services or connection
- [ ] The sandbox network is `internal`
- [ ] The fix diff will not stop the service from starting or accepting connections

---

## 2. To developers who modify or fork the tool

- **Do not create paths that bypass ScopeGuard.** Every new active capability must go through `ScopeGuard.authorize(...)`; if a new action class is needed, make it denied by default.
- **Do not add flags, environment variables or hidden options that disable the guard.**
- **Do not delete or disable safety tests.** A change that makes them fail may be weakening safety.
- **When implementing proposed features (such as Sentinel Mesh)**, respect every safety constraint in [Concept and Architecture 13.4](01_concept-and-architecture.md#134-sharing-block-decisions-signed-and-agreed) and [Paper 6.6](03_paper.md#66-safety-constraints-mandatory-for-any-implementation).
  In particular, "only accept block proposals from other nodes", "each node's own guard decides" and "never block the allowlist" are mandatory.
- **Do not add new exploit code, generic attack payloads or detection-evasion features.**
- If you publish a modified version, **state clearly that it is modified and whether any safeguard was changed**.

---

## 3. To those who redistribute or present the tool

- Do not present it as a "hacking tool" or "attack tool". It is **a tool for defense and authorized self-assessment**.
- "Multi-PC cooperation" and "blockchain integration" are **proposals and not implemented**. Do not present them as existing features.
- Always distribute the LICENSE, the Terms of Use, this document and the Disclaimer together with it.

---

## 4. To researchers and educators

- Run experiments in isolated environments you prepare yourself (virtual machines, isolated networks).
- If students use it, teach them the relevant law and ethics beforehand, and have the instructor provide the target environment.
- If your research finds a vulnerability, follow coordinated vulnerability disclosure.
  In Japan, the "Information Security Early Warning Partnership" run by IPA and JPCERT/CC is available.

---

## 5. If you find a vulnerability in this tool

Report it privately as described in [SECURITY.md](../../SECURITY.md), not in a public issue.
**A way to bypass the guard is treated as the most severe kind of vulnerability.**

---

## 6. If you are in trouble or have been attacked

Contact your local law enforcement's cybercrime unit and your national CERT/CSIRT. In Japan, for example:

- unauthorized-access damage: the cybercrime consultation desk of your prefectural police;
- incident-response advice: JPCERT/CC;
- general information-security advice: IPA's information security consultation desk.

(Contact details change; check each organization's official website for current information.)

---

Related: [Concept and Architecture](01_concept-and-architecture.md) / [Usage guide](02_usage-guide.md) / [Paper](03_paper.md) / [Disclaimer](05_disclaimer.md)
