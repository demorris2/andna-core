# AN-DNA Post-Packet Status Addendum

Status: addendum to the independent cryptographic review packet — not a replacement  
Main-branch HEAD at time of writing: `225b106da7399f9e21590348b69c7f4f90a9d722`  
Packet baseline tag: `vnext-phase1-r1-rc1` (commit `d9b7209345b9300e3468d587109cc0fca2ebbb29`)

---

## 1. Packet baseline

The independent cryptographic review packet, tagged `vnext-phase1-r1-rc1`, covered R1 as a built and CI-backed layer: the ML-DSA-44 frame verifier (via liboqs), the HMAC software-integrity path (Path A'), ACVP-derived KAT vectors, and cross-host reproducibility established through the Docker/HostB lane (Gate 2) with a pinned Gate 1 golden hash. D0 (the SHAKE256 epoch-ratchet identity derivation) and R2 (the OQS-free local policy/authorization engine) were fully specified in that packet but were not claimed as production components — they were presented for cryptographic review, not as shipping software.

---

## 2. Changes merged since packet

The following work was merged to main between `vnext-phase1-r1-rc1` and the current HEAD. This section is derived from `git log --oneline vnext-phase1-r1-rc1..HEAD`.

### HMAC integrity finalization (`a2754af`, tag `r1.0.0-hmac-integrity`)

Converged the FIPS documentation package to the post-HMAC state, verified the cross-host bit-identical reproducibility claim, finalized the two-artifact integrity bundle (`libandna_ffi.so` + `libandna_ffi.integrity`), and established the Docker/HostB lane as the sole authoritative reproducibility path. This closed the last open P0 items from the packet's FIPS annex.

### D0-R1 interop and procurement gate (`475ad0c`)

Wired D0 end-to-end with R1 to confirm the epoch-ratchet identity feeds correctly into R1 frame generation and verification. Added the `andna-d0 (procurement-grade gate)` CI lane (`.github/workflows/andna-d0.yml`) to enforce that `andna-d0` carries no OQS/liboqs dependency, consistent with the review packet's boundary claims.

### R2 pipeline and file-seal MVP (`2875217`)

Implemented the R2 local policy engine (`crates/andna-r2`), the `andna-pipeline` composition crate (`.crates/pipeline`) that sequences R1 verification followed by R2 authorization, and the initial file-seal verification path in `crates/andna-seal`. R2 is and remains OQS-free; the dependency boundary is CI-enforced via `cargo tree`.

### File-seal CLI, evidence v1, and file-seal CI lane (PR #2, `30eeeee`)

This is the primary productization milestone since the packet. It added:

- the four-command CLI surface: `init-sealer`, `seal-file`, `inspect-seal`, `verify-file`
- the `andna-seal-evidence-v1` evidence contract, with a deterministic section (replayable decision fields), an evidence digest (`SHA3-256` over the canonical deterministic encoding), and a digest-exempt runtime section
- evidence attestation: the evidence record is itself sealed as another artifact so that later edits to the evidence file are detected as file tamper
- forged-evidence rejection: an edited deterministic section breaks digest consistency and the attested evidence file verifies as `UNCHANGED: no`, `RESULT: REJECT`
- the `file-seal-lane` CI workflow (`.github/workflows/file-seal.yml`), covering formatting, R2 backend isolation, seal/evidence library tests, R1→R2 pipeline tests, and the operator CLI contract
- the operator contract script (`scripts/file_seal_cli_contract.sh`), which builds the CLI, runs the four-command surface, checks evidence output, and validates expected failure modes

### Workspace governance (PR #3, `225b106`)

Added `publish = false` to all workspace crates, established a valid `cargo deny` policy (`deny.toml`), created the `governance` CI lane (`.github/workflows/governance.yml`) to enforce the deny policy on relevant pushes, and added `kat_vector_gen` to `.gitignore`.

---

## 3. What these changes do not claim

These changes are engineering hardening and productization around the built R1 layer. None of them expand the cryptographic claims under review.

The governing language boundary is `docs/file-seal/file-seal-claim-boundaries.md`. The following is prohibited in all public-facing language derived from this work: hardware custody, clone resistance, FIPS-validated, ACVP-tested cryptographic module, file encryption, replacement for Sigstore/SLSA/TUF/in-toto, "impossible to forge", "unbreakable", or "military-grade."

The evidence-attestation flow is explicitly bounded: a party with signing material can create new evidence or new attestations. The current value is explicit replayability, digest consistency, and tamper detection against a specific sealed evidence artifact. See the claim-boundaries doc for the full "What this is not" list.

Terminology check: current repository code and documentation use SHAKE256 hash-chain ratcheting for D0 and SHAKE256 transcript binding for R1. No HKDF references were found in the current repo grep for HKDF/SHAKE/ratchet/forward. If older review materials contain HKDF wording, that wording should be treated as stale and corrected before redistribution.

---

## 4. Current main-branch status

### Green CI lanes (automatic, as of HEAD `225b106`)

| Workflow name | File | Scope |
| --- | --- | --- |
| `file-seal-lane` | `.github/workflows/file-seal.yml` | Formatting, R2 backend isolation, seal/evidence tests, pipeline tests, CLI contract |
| `governance` | `.github/workflows/governance.yml` | `cargo deny check`, workspace publish policy |
| `andna-d0 (procurement-grade gate)` | `.github/workflows/andna-d0.yml` | D0 unit tests, D0 OQS-free boundary |
| `r1-hmac-integrity-smoke` | `.github/workflows/r1-hmac-integrity-smoke.yml` | R1 HMAC software-integrity Path A' end-to-end |

The `HostB Rust Proof (Docker Lane)` (`.github/workflows/hostb_rust_proof.yml`) is manual dispatch and was established at the `r1.0.0-hmac-integrity` milestone.

### Local validation test counts (from CLAUDE.md, reflecting CI-green state)

```text
cargo test -p andna-seal --locked       15 passed
cargo test -p andna-pipeline --locked    4 passed
bash scripts/file_seal_cli_contract.sh  PASS: file-seal CLI contract
```

These commands are the authoritative local check before any commit touching the file-seal lane. The file-seal CI lane runs the equivalent checks on Linux (ubuntu-latest) on every push.

---

## 5. Review implications

The changes documented in section 2 represent post-packet engineering hardening and productization around the built R1 layer. They do not alter the cryptographic claims under review: the ML-DSA-44 signing and verification, the SHAKE256 transcript binding, the HMAC software-integrity path, or the ACVP KAT vectors are unchanged. D0 and R2 remain review-scoped components — no production claims have been added for either. The file-seal and governance lanes are operational evidence that R1's built verification path is being exercised correctly at the CLI and library levels, and that the workspace meets minimal supply-chain hygiene requirements. Reviewers should treat section 2 as context for the engineering state, not as a request to expand the review scope.

---

## 6. Recommended next work after review

The following items are already designed and waiting on the review outcome before any implementation proceeds, consistent with the active review freeze stated in `CLAUDE.md`.

**D0-ratchet signer backend with verify-as-of-snapshot semantics.** The design is complete: a signer that advances the D0 ratchet and stamps a registry snapshot at seal time, enabling a verifier to confirm identity state as of the sealing moment. This is the natural next step for making the file-seal lane production-viable and is frozen pending review.

**ML-KEM envelope (later, separate review item).** Adding a post-quantum key-encapsulation envelope around sealed artifacts is a planned future capability. It would be introduced as a separate cryptographic mechanism with its own review engagement, entirely distinct from the current ML-DSA-44 review scope.
