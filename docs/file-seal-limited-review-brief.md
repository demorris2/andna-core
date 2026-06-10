# AN-DNA File-Seal — Limited Review Brief

Status: limited, targeted review ask for the file-seal evidence v1 layer  
Scope: file-seal layer only — D0 ratchet internals and R2 policy security are out of scope for this brief  
Main-branch HEAD: `225b106da7399f9e21590348b69c7f4f90a9d722`  
Claim-boundaries reference: `docs/file-seal/file-seal-claim-boundaries.md`

---

## 1. What Is Built

AN-DNA File-Seal is a deterministic trust-evidence layer for consequential files and artifacts. It separates authenticity, unchanged-state, and authorization checks, then records the combined decision in a replayable evidence record.

### Four-command CLI surface

| Command | What it does |
| --- | --- |
| `init-sealer` | Generates local seed material and device identity; writes a software-profile JSON file |
| `seal-file` | Seals a file into a detached sidecar (`.andna-seal.json`); binds the file manifest hash into a signed R1 frame; writes a registry snapshot |
| `inspect-seal` | Structural inspection of a sidecar: checks frame length, epoch/device fields, and `ctx_hash` binding without performing full R1 verification |
| `verify-file` | Runs the full R1 → R2 pipeline; emits `ACCEPT` or `REJECT` with explicit per-check verdicts; optionally writes an `andna-seal-evidence-v1` evidence record |

### Evidence v1

`verify-file --evidence-out <path>` produces a stable `andna-seal-evidence-v1` JSON record. Its structure separates:

- **deterministic section**: the replayable decision core — `result`, `authentic`, `unchanged`, `authorized`, identity fields, hash fields, registry fields. This section is a pure function of the sealed bundle, the file bytes presented to verification, and the registry snapshot.
- **evidence_digest_hex**: `SHA3-256` over the canonical deterministic encoding (domain-separated, fixed field order, length-prefixed strings, explicit option tags). The digest covers the deterministic section only.
- **runtime section**: local paths, tool version, and timestamp — informational, digest-exempt.

### Attestation and forged-evidence rejection

`verify-file --attest-profile` seals the evidence record as another artifact using the existing file-seal path. A verifier can then confirm that a specific evidence file remained unchanged. Editing a deterministic field breaks digest consistency; if the evidence file is attested, it also returns `UNCHANGED: no`, `RESULT: REJECT`.

A party with signing material can produce new evidence or new attestations. The tamper-detection property holds against parties without signing material.

### CI-backed test evidence

| Evidence | Location |
| --- | --- |
| `andna-seal` library tests (15 passed) | `crates/andna-seal/tests/evidence_contract.rs` (6), `tests/file_seal_verify.rs` (9) |
| `andna-pipeline` end-to-end tests (4 passed) | `crates/pipeline/tests/d0_r1_r2_pipeline.rs` |
| Operator CLI contract | `scripts/file_seal_cli_contract.sh` → `PASS: file-seal CLI contract` |
| `file-seal-lane` CI workflow | `.github/workflows/file-seal.yml` |
| `governance` CI workflow | `.github/workflows/governance.yml` |

The `file-seal-lane` runs formatting, R2 backend isolation, seal/evidence library tests, pipeline tests, and the operator CLI contract on Linux (ubuntu-latest) on every push to relevant paths and every PR into main.

---

## 2. System Sketch

The file-seal path from file bytes to final evidence record:

```
  FILE BYTES
      │
      │  SHA3-256(canonical file bytes)
      ▼
  file_hash_hex  ─────────────────────────────────────────────┐
                                                               │
  seal-file:                                                   │
    canonical manifest { filename, content_type,              │
                         file_hash_hex, byte_length }         │
      │                                                        │
      │  SHA3-256(manifest encoding)                          │
      ▼                                                        │
  manifest_hash_hex                                           │
    = ctx_hash placed in ML-DSA-44 signed frame               │
      │                                                        │
      │  ML-DSA-44 Sign(sk, mu)                               │
      │  mu built from SHAKE256 transcript over message+nonce │
      ▼                                                        │
  SIDECAR (.andna-seal.json)                                  │
  { signed frame, T_E epoch-key structure }                   │
                                                               │
  ─────────────────── verify-file ────────────────────────── │ ─
                                                               │
  R1 VERIFY FRAME                                             │
    ML-DSA-44 signature check                                 │
    SHAKE256-64(pk_epoch ‖ epoch ‖ device_id16) = te_hash_hex │
    te_hash_hex == frame.pk_hash  →  authentic = yes/no       │
    frame.ctx_hash == manifest_hash_hex  (binding confirmed)  │
      │                                                        │
      │  on authentic=yes                                      │
      ▼                                                        │
  R2 AUTHORIZE (OQS-free)                                     │
    device_id32 ↔ registry snapshot entry                     │
    → authorized = yes / no / not_evaluated                   │
      │                                                        │
      ▼                                                        │
  COMBINED DECISION                                           │
    result = ACCEPT  iff  authentic=yes ∧ unchanged=yes       │
                          ∧ authorized=yes                     │
    unchanged check: recompute manifest, compare ctx_hash  ───┘
      │
      │  SHA3-256(domain-separated canonical encoding
      │           of deterministic section)
      ▼
  evidence_digest_hex  (in andna-seal-evidence-v1 record)
```

**Hash roles — do not conflate:**

| Hash | Role |
| --- | --- |
| SHA3-256 | `file_hash_hex` (manifest), `manifest_hash_hex` / `ctx_hash` (seal binding), `frame_hash_hex` (frame identity), `evidence_digest_hex` (evidence digest), `registry_snapshot_hash_hex` |
| SHAKE256 | `te_hash_hex`: 64-byte SHAKE256 over `(pk_epoch ‖ epoch ‖ device_id16)` — R1 epoch-key binding and device-id duality; also used internally by ML-DSA-44 (`mu` in the signing transcript) |

---

## 3. D0 Terminology

D0 terminology: D0 is described as a deterministic SHAKE256 hash-chain ratchet with domain separation. This brief does not introduce HKDF terminology. Review questions should be framed around the SHAKE256 ratchet construction, full-state dependence, predecessor recovery resistance, and the deterministic clone/offline-continuity tradeoff.

---

## 4. Threat Model — File-Seal Layer Only

This threat model covers only the file-seal layer. D0 ratchet internals and R2 policy security are explicitly out of scope for this brief.

### Trust assumption

The sealer's signing key material (software-profile seed) and the verifier's seed are local software secrets. The registry snapshot is a non-secret artifact: it is committed alongside sealed artifacts and is public by design. File bytes, sidecar, and evidence records are also non-secret.

### In-scope adversary: no signing material

An adversary without the sealer's seed material cannot produce a frame that passes R1 verification for a given device identity. AN-DNA provides the following detection guarantees against this adversary:

| Adversary action | Detection mechanism | Evidence field |
| --- | --- | --- |
| Edits file bytes after sealing | `file_hash_hex` recomputed at verification ≠ manifest value | `unchanged = no`, `unchanged_detail = file_hash_mismatch` |
| Edits filename or content-type in manifest | `manifest_hash_hex` recomputed ≠ `ctx_hash` in frame | `ctx_hash matches: no` (inspect), `authentic = no` (verify) |
| Edits raw sidecar bytes (frame) | ML-DSA-44 signature check fails | `authentic = no`, `verify_error = signature_invalid` |
| Edits deterministic fields in evidence record | `evidence_digest_hex` recomputed ≠ stored digest | digest-consistency check fails |
| Substitutes evidence record under existing attestation | `file_hash_hex` in attestation-verify ≠ new evidence bytes | attested verify: `unchanged = no`, `RESULT: REJECT` |

The `inspect-seal` command provides a structural pre-check (frame length, epoch fields, `ctx_hash` binding) without full R1 verification. Structural inspection alone does not confirm authenticity.

### Partial in-scope: adversary holds sealer or verifier seed

If an adversary obtains the sealer's seed, they can produce new valid frames and sidecars for arbitrary files. If they obtain the verifier's seed, they can produce new valid evidence attestations. Detection in this scenario relies on registry revocation or freeze — the operator removes or invalidates the relevant registry entry. This is the honest boundary: the file-seal layer provides no additional protection against an adversary who holds the seed. Rotate the seed (generate a new software profile) to establish a new identity; the prior registry entry should then be revoked.

### Out of scope for this brief

- D0 ratchet security: predecessor recovery resistance, full-state dependence, epoch-advance properties
- R2 policy security: authorization logic correctness, registry integrity outside the snapshot commitment

---

## 5. What Is Not Claimed

The file-seal MVP does not claim to be:

- hardware-backed custody
- clone-resistant identity
- a physical badge security system
- enterprise IAM
- file encryption
- a FIPS-validated module
- an ACVP-tested cryptographic module
- a replacement for Sigstore, SLSA, TUF, or in-toto
- production-ready key management
- proof that a human personally approved an artifact
- proof that a file is safe, malware-free, or semantically correct

Full claim-boundary language and approved framing: `docs/file-seal/file-seal-claim-boundaries.md`.

The current `init-sealer` profile is demo/MVP scoped. It generates local seed material and a local software-profile JSON file. It is not hardware-backed, does not prevent cloning, and is not a substitute for a hardware security module or enterprise key custody.

---

## 6. Specific Reviewer Asks

This brief requests a limited, targeted review of the file-seal evidence v1 layer. Specific questions for the reviewer:

1. **Are the claims accurate?** Do the detection guarantees in section 4 accurately describe what the cryptographic construction provides? Are there conditions under which the claimed detection fails that are not stated?

2. **Is the threat model coherent?** Is the boundary between "adversary without signing material" and "adversary with signing material" drawn correctly? Is the seed-compromise section an honest statement of the layer's limits?

3. **Is the evidence boundary clear?** Does the separation between the deterministic section (digest input) and the runtime section (digest-exempt) create any ambiguity about what the evidence digest actually covers? Is the canonical encoding description (domain separation, fixed field order, length-prefixed strings, option tags) sufficient to evaluate digest security?

4. **Are there dangerous ambiguities?** Are there any statements in the brief, the claim-boundaries doc, or the evidence-v1 doc that could be misread to imply stronger guarantees than the construction provides?

5. **What must be reviewed before stronger claims?** What additional review or evidence would be required before the file-seal layer could support claims beyond the current bounded set (e.g., a claim about the security of the software-profile sealer as a production key-management mechanism)?

---

## 7. Replay Semantics — Precision Required

Replay semantics in this system have two distinct levels. Conflating them is a known overclaim hazard.

### Digest-consistency checking (evidence record alone)

Given only an `andna-seal-evidence-v1` JSON record, a verifier can:

1. re-encode the deterministic section using the v1 canonical encoding (domain separation `ANDNA-SEAL-EVIDENCE-v1`, fixed field order, length-prefixed strings, explicit option tags, little-endian integers)
2. compute `SHA3-256` over that encoding
3. compare the result to `evidence_digest_hex`

If they match, the deterministic fields have not been altered since the digest was produced. This is **digest-consistency checking**. It does not confirm that the original verification produced those field values; it confirms only that the fields have not been edited after the digest was computed.

### Full replay (original inputs required)

Full replay confirms that the deterministic section is correct for a specific sealed bundle. It requires all original inputs:

- the original file bytes
- the original sidecar (`.andna-seal.json`)
- the original registry snapshot

The verifier runs `verify-file` against those inputs and compares the resulting deterministic section and `evidence_digest_hex` to the stored record. If they match, the evidence record is replay-consistent with the original verification.

### What the evidence file alone does not support

An evidence JSON record alone does not support full replay. The evidence file records what the verifier decided and what inputs were hashed, but it does not embed the file bytes, the sidecar frame, or the registry snapshot. A verifier who holds only the evidence file can check digest consistency; they cannot re-run the verification.

The attested-evidence path (`--attest-profile`) seals the evidence file as another artifact. Verifying the attestation confirms the evidence file is unchanged; it does not substitute for full replay.

---

## Appendix: Key File Locations

| Artifact | Location |
| --- | --- |
| Evidence contract documentation | `docs/file-seal/file-seal-evidence-v1.md` |
| Claim boundaries | `docs/file-seal/file-seal-claim-boundaries.md` |
| CI lane documentation | `docs/file-seal/file-seal-ci-lane.md` |
| CLI demo and operator walkthrough | `docs/file-seal/file-seal-cli-demo.md` |
| Operator contract script | `scripts/file_seal_cli_contract.sh` |
| Seal + evidence library | `crates/andna-seal/` |
| Pipeline (R1 → R2 composition) | `crates/pipeline/` |
| R2 policy engine | `crates/andna-r2/` |
| R1 frame verifier (frozen) | `crates/core/` |
| CLI binary source | `ffi_cli/` |
