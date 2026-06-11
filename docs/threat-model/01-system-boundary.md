# 01 — System Boundary

## Generation boundary (load-bearing statement)

The shipping build is **vNext: ML-DSA-44 + SHAKE256**.

The retired design — v3.2/v3.3: custom Ring-LWE epoch-mutation + HKDF-SHA512, ring modulus
q = 3 329 — is an **archived design record**, not the current basis. Any corpus material that
refers to Ring-LWE leakage analysis, a ZK "God-mode verifier" premise, or shared-state
disclosure describes the retired design. Those materials are archived, not operative.

**Verifiable tell in live code.**  `D0_P_Q = 8 380 417` is the ML-DSA modulus (FIPS 204).
The retired design used q = 3 329 (the Kyber/Ring-LWE modulus). The current value is an
observable, machine-checkable constant in `crates/andna-d0/src/derive.rs:38`. This is not
a claim — it is a value that can be read directly from the source.

## Built / true today

### D0 — epoch/state derivation (review-scoped, partially implemented)

- SHAKE256 hash-chain ratchet; spec version `D0_SPEC_VERSION = 0x02`.
- Ring modulus q = 8 380 417 (ML-DSA; confirms generation boundary above).
- Three domain-separated SHAKE256 labels: `ANDNA-D0-EPOCH-SEED-v1`,
  `ANDNA-D0-MLDSA-SEED-v1`, `ANDNA-D0-RATCHET-STATE-v1`.
- Mod-bias-free rejection sampling (`REJECT_BOUND`).
- Full-state-dependence invariant R-1 coded and commented.
- Deterministic ratchet public entry only; connected-healing slot reserved and inactive
  (see `02-d0-state-custody-and-clone.md`).
- Zeroization on `SecretState` drop.

### R1 — ML-DSA-44 public-verifier (built, engineering complete)

- Canonical Frame v2 layout: `mu_pre (274 B) || T_E (1 336 B) || sig (2 420 B)`.
- Transcript binding: pk_hash (SHAKE256 over T_E), epoch, device_id32, domain separator.
- Four verifier directives checked in order: pk_hash → epoch → device_id32 → ML-DSA verify.
- `inspect-seal` performs structural inspection only; does not imply ACCEPT.
- Remaining P0: external CST-lab ACVP session (not an engineering gap).

### R2 — local policy/authorization (MVP)

- Evaluates authorization against the SUPPLIED registry snapshot.
- Fail-closed: R1 reject gates R2 (R2 is NOT_EVALUATED on CRYPTO_REJECT).
- Snapshot-bound policy digest; records `snapshot_seq`, `as_of_unix_ms`, `snapshot_hash`.
- Strict epoch-freshness check (frame epoch must equal registry `current_epoch`).
- Authorization states: `AUTHORIZED`, `NOT_AUTHORIZED`, `NOT_EVALUATED`.

### File-seal — product wedge over R1/R2

- Detached sidecar creation and structural inspection.
- Manifest hash binding (file hash + file name + file size → ctx_hash in frame).
- Seal → Verify → ACCEPT/REJECT decision with three explicit verdicts: AUTHENTIC,
  UNCHANGED, AUTHORIZED.
- Evidence output under `andna-seal-evidence-v1` schema.

### Evidence v1 — deterministic record + digest

- Deterministic section byte-identical across repeated verifications of the same inputs.
- Evidence digest covers only the deterministic section; runtime fields excluded.
- `digest_consistent()` detects in-place edits to the deterministic section.

### Demo UI — presentation shell

- Thin Streamlit shell that invokes the CLI and displays its JSON output.
- **Contains no verification logic.** All decisions are made by the Rust CLI path.
- The evidence JSON displayed by the UI is produced by the CLI, not the UI.

## Authoritative path

The Rust CLI is the authoritative verification engine. The Python demo UI is a display
layer. The evidence JSON alone is not full replay (see `05-evidence-semantics-and-replay.md`).
The software-profile sealer is demo/MVP scoped — not production key custody.

## Not yet built (future mitigations)

Hardware identity attestation, cloud-backed registry with signed snapshots, non-exportable
key storage, attested enrollment, epoch-velocity policy enforcement, multi-device lineage.

## Reviewer questions

1. Is the generation-boundary statement (vNext vs retired) clear enough for a reader who
   has only seen the v3.3 Security Appendix?
2. Are there other corpus materials that reference the retired Ring-LWE design that should
   be explicitly listed as archived?
