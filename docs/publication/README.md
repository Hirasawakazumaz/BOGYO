# BOGYO Documentation

> **Status: prepared for publication.** These documents describe BOGYO 0.1.0.

> **Snapshot note:** these documents describe the BOGYO 0.1.0 code as of 2026-10-18. Since then the multi-node mesh has been **implemented** (rolling-key channel, signed patch chain, and a sandbox conflict gate before apply) — see [../WHITEPAPER.md](../WHITEPAPER.md) §4 and [../MESH_SETUP.md](../MESH_SETUP.md). Statements below that call the mesh a proposal or "not implemented" are out of date.

| # | Document | Contents | For |
|---|----------|----------|-----|
| 01 | [Concept and Architecture, Illustrated](01_concept-and-architecture.md) | The defense philosophy (get there first, multi-PC cooperation, composite chain) and the internal structure, explained with 15 diagrams | Engineers, researchers |
| 02 | [Usage Guide](02_usage-guide.md) | Step by step from installation through daily operation to emergency stop | Operators |
| 03 | [Paper](03_paper.md) | "Consent-Gated Proactive Self-Defense and a Layered Tamper-Evident Ledger against AI-Accelerated Attacks" | Researchers, reviewers |
| 04 | [Requests for Safe Use](04_safe-use-requests.md) | Requests and prohibitions for users, developers, redistributors and researchers | Everyone |
| 05 | [Disclaimer](05_disclaimer.md) | No warranty, limitation of liability, user responsibility | Everyone |

Diagrams are written in Mermaid and render directly on GitHub. Static SVG versions for print are in
[`figures/`](figures/) (`<doc>-figNN.svg`).

## Implemented vs. proposed

Every capability is labelled in these documents:

- **[Implemented]** — exists as code in this repository and is covered by tests.
- **[Proposal — not implemented]** — design and proposed architecture only; there is no code yet.

In particular, **multi-PC cooperation and the blockchain-based composite ledger ("BOGYO Mesh") are proposals and are not implemented.**
What the code has today is their foundation: a **single-node hash-chained audit log**, **Ed25519 signatures** and **canonical hashing**.

## Accompanying material

| Path | Contents |
|------|----------|
| [`eval/bench_audit_guard.py`](eval/bench_audit_guard.py) | Reproduces the measurements in Section 8 of the paper (uses temporary directories only, no network) |
| [`eval/results-2026-10-18.json`](eval/results-2026-10-18.json) | Results of that script |
| [`build.sh`](build.sh) | Builds standalone HTML into `docs/publication/dist/` (not tracked in Git) |

