# AN-DNA Threat Model — Index

Status: **review freeze active** — documentation and characterization tests only.
No crypto changes, no new mechanisms, no feature activation.

---

## System boundary (ASCII diagram)

```
┌─────────────────────────────────────────────────────────────────────┐
│                     AN-DNA vNext (R1 scope)                         │
│                                                                     │
│  ┌──────────┐   state    ┌──────────┐   frame    ┌───────────────┐  │
│  │   D0     │──────────>│  R1      │──────────>│  R2            │  │
│  │ ratchet  │  (epoch    │ verifier │  (ACCEPT   │ authorization  │  │
│  │ (review- │   key,     │ (built)  │   only)    │ (MVP/local)    │  │
│  │  scoped) │   T_E)     └──────────┘            └───────────────┘  │
│  └──────────┘                 │                         │           │
│                               │ ACCEPT/REJECT           │ AUTH/NOT  │
│                               ▼                         ▼           │
│                      ┌────────────────┐       ┌─────────────────┐   │
│                      │  File-seal     │       │  Evidence v1    │   │
│                      │  (MVP wedge)   │──────>│  (built)        │   │
│                      └────────────────┘       └─────────────────┘   │
│                               │                         │           │
│                               ▼                         ▼           │
│                      ┌────────────────┐       ┌─────────────────┐   │
│                      │  Demo UI       │       │  Audit log      │   │
│                      │  (thin shell)  │       │  (local chain)  │   │
│                      └────────────────┘       └─────────────────┘   │
│                                                                     │
│  Boundary note: the Rust CLI is the authoritative engine.           │
│  The Python UI contains no verification logic.                      │
└─────────────────────────────────────────────────────────────────────┘

Outside scope (future): hardware HSM, cloud registry, attested enrollment,
                         external audit anchoring, ZK (future research only)
```

---

## Built-vs-specified table

| Layer | Status | Key gap / future item |
|---|---|---|
| D0 ratchet (hash-chain, SHAKE256) | Review-scoped | Clone resistance; connected-healing inactive |
| D0 domain separation | **SATISFIED** | — |
| R1 ML-DSA-44 verifier | Built (ACVP lab pending) | ACVP completion |
| R2 local authorization | MVP | Signed snapshots; staleness floor; revocation timestamp |
| File-seal | Built | Production key custody |
| Evidence v1 | Built | `check-evidence` / `replay` CLI commands not yet shipped |
| Demo UI | Built (thin shell) | — |
| Audit log | Built (local) | External anchoring; witness cosigning |
| Enrollment / provisioning trust | Review-scoped | Attested enrollment; provenance-signed entries |

---

## Document index

| Doc | Title | Primary concern |
|---|---|---|
| **01** | [System Boundary](01-system-boundary.md) | Generation boundary; component inventory |
| **02** | [D0 State Custody and Clone](02-d0-state-custody-and-clone.md) | Ratchet; clone; healing |
| **03** | [R1 Verifier Boundary](03-r1-verifier-boundary.md) | Frame layout; verifier directives |
| **04** | [R2 Registry Freshness and Revocation](04-r2-registry-freshness-and-revocation.md) | Staleness; rollback; revocation |
| **05** | [Evidence Semantics and Replay](05-evidence-semantics-and-replay.md) | What the evidence JSON proves |
| **06** | [Audit Chain and Split World](06-audit-chain-and-split-world.md) | Local log; fork; truncation |
| **07** | [File-Seal Demo and Software-Profile Boundary](07-file-seal-demo-and-software-profile-boundary.md) | Demo scope; UI architecture |
| **08** | [Claim Boundary Matrix](08-claim-boundary-matrix.md) | Allowed / blocked language |
| **09** | [Enrollment and Provisioning Trust](09-enrollment-and-provisioning-trust.md) | GIVDO at provisioning time |

Claim-boundary reference: [docs/file-seal/file-seal-claim-boundaries.md](../file-seal/file-seal-claim-boundaries.md)

---

## Characterization test suite (Branch B)

Branch `test/threat-model-characterization` contains new integration test files that pin
already-built deterministic behavior. No `src/` files are modified; tests only assert
existing public API behavior.

| Test file | Maps to doc | Coverage |
|---|---|---|
| `crates/andna-d0/tests/d0_characterization.rs` | 02 | Domain-label distinctness; healing-guard patterns; ratchet reproducibility |
| `crates/andna-seal/tests/r1_inspect_boundary.rs` | 03 | `inspect-seal` cannot imply ACCEPT |
| `crates/andna-r2/tests/r2_characterization.rs` | 04 | Policy-version current behavior; stale-snapshot placeholder (ignored) |
| `crates/andna-seal/tests/evidence_characterization.rs` | 05 | `digest_consistent()` is not replay |

Run characterization tests:
```
cargo test -p andna-d0 --locked
cargo test -p andna-seal --locked
cargo test -p andna-r2 --locked
```

---

## Consolidated reviewer questions

From doc 01:
1. Is the generation-boundary statement (vNext vs retired) clear enough for a reader who
   has only seen the v3.3 Security Appendix?

From doc 02:
2. Is the "revocation is the only current fallback" finding stated plainly enough?
3. Should the healing-source options be ranked by security strength?

From doc 03:
4. Should the zero ctx_hash risk in non-file-seal use cases be flagged?
5. Is the test suite sufficient evidence for the four-directive ordering guarantee?

From doc 04:
6. Is the stale-snapshot gap critical for any production deployment, or acceptable for pilot?
7. Is the device_id16 vs device_id32 lookup ambiguity worth a design note?

From doc 05:
8. Should the evidence JSON carry a human-readable "replay requires original inputs" field?
9. Should `check-evidence` and `replay` CLI commands be tracked as R1.1 scope items?

From doc 06:
10. For pilot use, is the split-world gap acceptable if auditors hold independent log copies?
11. Should the CLI emit a chain-tip hash on exit as an anchor hint?

From doc 07:
12. Should the demo registry include a second sealer to demonstrate cross-device authorization?
13. Should `app.py` display a visible "verification is performed by the CLI" disclaimer?

From doc 09:
14. For pilot scope: is self-authorization (operator == sealer) explicitly acceptable?
15. Should a minimum enrollment ceremony be required before any production deployment?
