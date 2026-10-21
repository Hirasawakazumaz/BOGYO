# Legal notes (informational, not legal advice)

This summarizes why Sentinel-Guard's design stays within the law when used as intended.
It is **not legal advice**; consult a qualified lawyer for your situation.

## Core principle
Acting on **systems you own or are explicitly authorized to test** is lawful.
Acting on systems **without authorization** is not, in essentially every jurisdiction.
Sentinel-Guard enforces the former with a signed scope and consent, and refuses the
latter by design.

## Japan
- **Unauthorized Computer Access Act** — Prohibits unauthorized access to others' computers. Testing
  your own servers with your own authority is not "unauthorized access". Third-party
  targets without written authorization would violate this. The signed scope enforces
  self-ownership.
- **Penal Code Arts. 168-2 / 168-3 (unauthorized command electromagnetic records)** — Creating/providing
  malware without legitimate cause. Sentinel-Guard ships no new exploit code and no
  generic attack payloads; it orchestrates legitimate, widely-used tools (nmap, nuclei,
  OWASP ZAP, trivy) for defense and authorized self-testing, with safeguards and terms.
- **Penal Code Art. 234-2 (obstruction of business by damaging a computer) / DoS** — Damaging/obstructing others'
  systems. Out of scope by design; attacks run only against your own isolated replicas.
- **Hack-back** — Retaliating against an attacker is not permitted under Japanese law.
  The tool only drops inbound traffic; it never sends traffic back to an attacker.

## International
- **US — CFAA**: unauthorized access/damage. Same self-ownership principle.
- **UK — Computer Misuse Act**: unauthorized access/impairment.
- **Germany — StGB §202c ("Hackerparagraf")**: restricts dual-use attack tools,
  including distribution. Sentinel-Guard mitigates this by (a) shipping no new attack
  code, (b) defaulting every active capability off, (c) hard-refusing out-of-scope and
  production attack targets, and (d) attaching terms limiting use to owned assets.
- **Budapest Convention on Cybercrime**: international framework behind many of the above.

## Design choices that keep it on the safe line
- Signed ownership scope + operator consent, verified before every run (fail closed).
- Default-deny toggles and dry-run by default.
- Attacks only against isolated sandbox replicas, never production.
- No hack-back; defense limited to inbound blocking.
- Tamper-evident audit log of every decision and action.
- Published with LICENSE additional-use notice, TERMS_OF_USE, and SECURITY policy.
