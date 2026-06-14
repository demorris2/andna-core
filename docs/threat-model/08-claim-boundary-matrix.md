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

## Reviewer questions

1. The D0 "review-scoped" status — does "review-scoped" need a more precise label (e.g.
   "specification complete, implementation review pending") to avoid ambiguity with "MVP"?
2. Is the ACVP lab engagement blocking status for the R1 "Built" claim, or is "engineering
   complete, lab pending" sufficient for the current review scope?
