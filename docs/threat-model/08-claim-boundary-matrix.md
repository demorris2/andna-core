# 08 — Claim Boundary Matrix

Reference: `docs/file-seal/file-seal-claim-boundaries.md` is the authoritative public-language
boundary. This matrix maps each capability layer to its status, allowed framing, and blocked
framing for reviewer and communications use.

| Claim | Status | Allowed wording | Blocked wording |
|---|---|---|---|
| **R1 verification** | Built; engineering complete (ACVP lab session pending) | "ML-DSA-44 signature verification over a canonical transcript binding epoch, device identity, and file manifest"; "verifies that the frame was signed by the keyed device at the stated epoch" | "FIPS-validated"; "ACVP-certified"; "quantum-proof"; "unbreakable" |
| **D0 ratchet** | Review-scoped | "SHAKE256 hash-chain ratchet under stated assumptions; domain-separated (SATISFIED — three distinct `-v1` labels); prior-state-recovery resistance under the assumption that past state is not retained; connected-healing slot reserved and inactive pending review" | "prevents cloning"; "clone-resistant"; "hardware-rooted"; "forward-secure without qualification" |
| **D0 domain separation** | SATISFIED | "Three distinct SHAKE256 domain labels (`ANDNA-D0-EPOCH-SEED-v1`, `ANDNA-D0-MLDSA-SEED-v1`, `ANDNA-D0-RATCHET-STATE-v1`); each derivation uses a distinct label" | "perfect domain separation" (unqualified) |
| **R2 authorization** | MVP / local | "Authorization evaluated against the supplied registry snapshot; fail-closed; snapshot-bound policy digest"; "R2 does not prove global or current authorization unless snapshot freshness and authority are separately established" | "real-time authorization"; "revocation-aware without qualification"; "global identity check" |
| **Evidence record** | Built | "Deterministic evidence digest over replayable decision fields; detects in-place edits to the deterministic section"; "`digest_consistent()` checks internal coherence of the stored record" | "evidence JSON alone replays"; "self-verifying"; "the evidence proves the file is safe" |
| **Demo UI** | Built — thin shell | "Presentation layer over the Rust CLI; displays CLI-produced JSON; contains no verification logic" | "the UI verifies files"; "the demo proves hardware identity"; "enterprise-grade" |
| **Software-profile sealer** | Demo / MVP | "Local seed generation for demonstration; operator must protect the profile file; enables local seal/verify demonstrations" | "hardware-backed custody"; "prevents cloning"; "production IAM"; "HSM-equivalent" |
| **Enrollment** | Review-scoped — trust root not yet analyzed | "Enrollment is currently out-of-band / operator-asserted; the sealer writes its own registry entry in demo/MVP" | "attestation-verified enrollment"; "hardware-attested key origin" (without qualification) |
| **Audit chain** | Built — local integrity only | "Append-only hash-linked local log; detects local tamper, duplication, deletion, reordering; single-writer" | "tamper-proof audit"; "distributed ledger"; "publicly auditable" (without external anchoring) |
| **File-seal overall** | Built — MVP wedge | "Deterministic trust-evidence layer; separates authenticity, unchanged state, and authorization; replayable evidence contract" | "encrypts files"; "replaces Sigstore/SLSA/TUF/in-toto"; "hardware custody"; "impossible to forge" |

## Banned words (carry-forward from claim-boundary doc)

These words must not appear in any external communication about the current build, regardless
of context:

- unbreakable
- impossible to forge
- hardware custody (without active HSM integration)
- FIPS-validated (ACVP session not yet complete)
- encrypts / encryption (file-seal does not encrypt)
- clone-proof (D0 does not currently prove clone resistance)
- replaces Sigstore / SLSA / TUF / in-toto

## Hash-role precision

| Hash function | Role in AN-DNA vNext |
|---|---|
| SHAKE256 | D0 ratchet state, D0 epoch seed, D0 ML-DSA seed; R1 transcript mu (SHAKE256 of mu_pre); pk_hash binding (SHAKE256 of T_E); device_id32 expansion |
| SHA3-256 | Evidence digest; R2 policy digest; registry snapshot hash; manifest hash (file hash + name + size) |
| HKDF-SHA512 | Retired v3.3 design ONLY — must not appear in any current-capability description |

## Security-level assumptions (F4 — L1 hardening)

All security-level claims in this project are stated WITH their underlying assumptions and a
dated cryptanalysis baseline. A security level is not a timeless absolute — it is a statement
relative to the best-known attacks at a specific date.

| Claim | Stated level | Assumption | Baseline date | Source |
|---|---|---|---|---|
| ML-DSA-44 (FIPS 204) | NIST Category 2 (≈128-bit PQ security) | Best-known lattice attacks as of the NIST PQC standardization, including quantum core-SVP sieving | 2024-08 (FIPS 204 publication) | NIST FIPS 204 §1; parameter selection rationale in the ML-DSA specification |
| SHAKE256 (FIPS 202) | 256-bit security strength | Best-known attacks on Keccak sponge construction | 2015-08 (SHA-3 publication); no known weakening as of 2025-08 | NIST FIPS 202; SHA-3 competition analysis |
| SHA3-256 (FIPS 202) | 128-bit collision resistance, 256-bit preimage | Same as SHAKE256 | Same as SHAKE256 | NIST FIPS 202 |
| D0 ratchet forward secrecy | Conditional on past-state erasure | Prior-state-recovery resistance ASSUMES past polynomial state `P_E` is not retained by any party; if past state is retained, forward secrecy does not hold | N/A (architectural assumption, not a cryptanalytic claim) | D0 spec v0.3 §14 |

**Rule inversion note (F4):** This project follows an "authority outranks recency" rule for
document integrity (older authoritative source wins over newer informal source). For security
margins, this rule INVERTS: recency of cryptanalysis is precisely what must be tracked, because
new attacks erode margins. A NIST category designation from 2024 may need re-evaluation if a
2026 result changes the core-SVP sieving exponent. Track both rules; do not let them collide.

**F4 scan result:** `git grep -niE 'delta|don.t change|do not change' crates/` — no hardcoded
security constant analogous to L1's `DELTA128 = 1.0044` found in any crate. ML-DSA-44
parameters are NIST-defined and consumed from liboqs/fips204, not hardcoded in this repo.

## Reviewer questions

1. The D0 "review-scoped" status — does "review-scoped" need a more precise label (e.g.
   "specification complete, implementation review pending") to avoid ambiguity with "MVP"?
2. Is the ACVP lab engagement blocking status for the R1 "Built" claim, or is "engineering
   complete, lab pending" sufficient for the current review scope?
