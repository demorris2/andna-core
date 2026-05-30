# AN-DNA FIPS 140-3 Algorithm Inventory

**Document:** `/fips/algorithm_inventory.md`
**Status:** Draft — Pre-CST Lab Submission
**Version:** 1.4.0
**Date:** 2026-05-30
**Prepared by:** Darrell Morris Jr. — ArcNeura
**Reference:** FIPS 140-3, FIPS 202, FIPS 204, FIPS 198-1, NIST SP 800-140C (CMVP
Approved Security Functions)

---

## 1. Overview

This document enumerates every cryptographic algorithm used within the AN-DNA Core
Verification Library boundary. CMVP examiners require a complete and accurate algorithm
inventory — any algorithm used but not listed, or listed but lacking a self-test, will halt
validation.

Three FIPS-approved algorithms are used within the boundary. One non-approved mechanism
(the stub backend) and one development-only software-integrity feature (`fips-integrity-stub`)
are explicitly documented and excluded from Approved Mode operation.

---

## 2. FIPS-Approved Cryptographic Algorithms

These algorithms are utilized in the Approved Mode of operation and are subject to
Cryptographic Algorithm Validation Program (CAVP) testing via ACVP at the CST lab.

### 2.1 ML-DSA-44

| Field | Value |
|---|---|
| **Algorithm** | ML-DSA-44 (Module-Lattice-Based Digital Signature Algorithm) |
| **Standard** | FIPS 204 |
| **Parameter Set** | ML-DSA-44 (NIST Security Category 2) |
| **Implementer / Crate** | `liboqs` 0.10.1 (via `andna-mldsa44` crate, `oqs-backend` feature) |
| **Approved Mode Use** | Yes |
| **Use in Module** | Signature verification — validates the ML-DSA-44 proof transcript `π = (z, h, c̃)` produced by the device's FSwA prover loop |
| **Key Parameters** | q = 8380417, n = 256, k = ℓ = 4, Ring: R_q = Z_q[X]/(X²⁵⁶ + 1) |
| **Signature Input** | 274-byte canonical `mu_pre` payload (SHAKE256-derived `μ`) |
| **CAVP Certificate** | TBD — issued by CST lab via ACVP |
| **Power-Up Self-Test** | Required — ML-DSA-44 Known Answer Test (KAT) for SigVer |
| **ACVP Test Type** | sigVer |
| **Notes** | Verification only at the FFI boundary. Sign operations occur on the device (prover); the module boundary covers the verifier path exclusively. |

### 2.2 SHAKE256

| Field | Value |
|---|---|
| **Algorithm** | SHAKE256 (Extendable-Output Function) |
| **Standard** | FIPS 202 |
| **Implementer / Crate** | `andna-transcript` crate (via `sha3` crate) and `liboqs` internal use |
| **Approved Mode Use** | Yes |
| **Use in Module** | (1) `pk_hash` derivation: `SHAKE256(Encode(T_E), 64)` — 64-byte hash of the Epoch Public Key bound into `mu_pre` at offset 0x0000. (2) `μ` derivation: `μ ← SHAKE256(mu_pre, 64)` — final 64-byte authentication payload hash fed to ML-DSA-44 verification. (3) Internal use by `liboqs` within ML-DSA-44 operations (ExpandMask, SampleInBall). |
| **Output Length** | 64 bytes (512 bits) for both `pk_hash` and `μ` derivations |
| **Domain Separation** | Enforced by fixed positional byte layout in `mu_pre`. ASCII string tags for XOF domain separation are prohibited per True vNext spec. |
| **CAVP Certificate** | TBD — issued by CST lab via ACVP |
| **Power-Up Self-Test** | Required — SHAKE256 Known Answer Test (KAT) |
| **ACVP Test Type** | AFT (Algorithm Functional Test) |
| **Notes** | SHAKE256 is used exclusively as an XOF (Extendable-Output Function), not as a fixed-length hash. Output length is always 64 bytes at the module boundary. |

### 2.3 SHA-3-256

| Field | Value |
|---|---|
| **Algorithm** | SHA-3-256 (Fixed-output hash function) |
| **Standard** | FIPS 202 |
| **Implementer / Crate** | `andna-audit` crate (via `sha3` crate) |
| **Approved Mode Use** | **No — used outside the FIPS cryptographic module boundary** |
| **Use in Module** | Tamper-evident audit chain hash chaining in `andna-audit`. SHA3-256 is distinct from SHAKE256 (XOF); this is a fixed-output hash used for audit log integrity only. |
| **Notes** | `andna-audit` is explicitly outside the FIPS boundary (see `module_boundary.md` Section 3.2). SHA3-256 in the audit chain is not a FIPS-approved service of this module. Listed for completeness per CMVP requirements. |

### 2.4 HMAC-SHA-256

| Field | Value |
|---|---|
| **Algorithm** | HMAC-SHA-256 |
| **Standard** | FIPS 198-1 (HMAC) + FIPS 180-4 (SHA-256) |
| **Implementer / Crate** | `andna-ffi` crate, `fips-integrity-hmac` feature (RustCrypto `hmac` 0.12 + `sha2` 0.10) |
| **Approved Mode Use** | Yes — used for the power-up software integrity self-test |
| **Use in Module** | (1) Software-integrity self-test: HMAC-SHA-256 of the module artifact (`libandna_ffi.so`) is computed and compared in constant time against the value embedded in an associated `ANDNA-INTEGRITY-v1` reference file. (2) Power-up HMAC CAST: validates the HMAC primitive against an RFC 4231 known-answer vector before the primitive is used for software integrity. |
| **Integrity Key** | Fixed, non-secret 32-byte key embedded in the module. See Section 7 (Non-Claims) for the bounded security claim. |
| **CAVP Certificate** | TBD — issued by CST lab via ACVP |
| **Power-Up Self-Test** | HMAC CAST runs first in the self-test sequence (see Section 4.1); the HMAC primitive is then used for the software integrity check (Section 4.4). |
| **ACVP Test Type** | AFT |
| **Status** | **Implemented (Path A′).** Replaces the prior `fips-integrity-stub` placeholder. Validated end-to-end against the release `libandna_ffi.so` in Docker and on GitHub Actions HostB; the smoke test passes for the valid module/reference pair (rc=0) and fails closed (rc=100) for missing env paths, tampered module bytes, and tampered reference content. |

---

## 3. Non-Approved Cryptographic Algorithms (No Security Claim)

These mechanisms are expressly non-approved and are not used in the FIPS Approved Mode
of operation. They are documented here for completeness per CMVP requirements.

| Algorithm / Mechanism | Standard | Implementer / Crate | Approved Mode Use | Notes |
|---|---|---|---|---|
| Stub Backend | N/A | `andna-mldsa44` (`stub` feature) | **No** | Always-pass verification shim used strictly for CI bootstrap during build pipeline testing. Produces no real cryptographic output. Excluded from FIPS boundary and Approved Mode by feature flag. The `oqs-backend` feature must be enabled and `stub` must be absent for any Approved Mode artifact. |
| `fips-integrity-stub` | N/A | `andna-ffi` (`fips-integrity-stub` feature) | **No — development only** | Development-only software-integrity shim that always passes. Crate-root `compile_error!` gates enforce that exactly one of `fips-integrity-stub` or `fips-integrity-hmac` is selected. Must not be present in any Approved Mode artifact. |

---

## 4. Cryptographic Self-Tests

To comply with FIPS 140-3, the module performs the following self-tests upon initialization
(power-up) before any FFI output is permitted. If any self-test fails, the module enters
the Error State and returns `AndnaErr::Internal` on all subsequent FFI calls until the
module is reloaded.

**Self-test order (locked):**

```
1. HMAC-SHA-256 CAST  →  2. SHAKE256 KAT  →  3. ML-DSA-44 KAT  →  4. Software Integrity Check
```

The HMAC primitive is self-tested before the software integrity check uses it. The existing
SHAKE256 and ML-DSA-44 KAT ordering is preserved from prior versions.

### 4.1 HMAC-SHA-256 Cryptographic Algorithm Self-Test (CAST)

| Field | Value |
|---|---|
| **Test Type** | Power-Up CAST |
| **Algorithm** | HMAC-SHA-256 (FIPS 198-1) |
| **Test Vector Source** | RFC 4231, Test Case 2 (key `"Jefe"`, data `"what do ya want for nothing?"`) |
| **Test Operation** | Compute HMAC-SHA-256 over the fixed vector; constant-time compare against the published 32-byte expected tag. |
| **Trigger** | `andna_init()` — step 0 of the self-test sequence under the `fips-integrity-hmac` feature |
| **Failure behavior** | Module enters Error State; all FFI functions return `AndnaErr::Internal` |
| **Tests location** | `crates/ffi/src/lib.rs` — `run_hmac_sha256_cast()` and unit tests |
| **Status** | **Implemented.** Passes under `fips-integrity-hmac`. |

### 4.2 SHAKE256 Known Answer Test (KAT)

| Field | Value |
|---|---|
| **Test Type** | Power-Up KAT |
| **Algorithm** | SHAKE256 (FIPS 202) |
| **Test Vector Source** | Internal — generated by `tests/generate_transcript_kats.py`, byte-identical to Python `hashlib.shake_256` reference |
| **Test Operation** | Three fixed-input vectors verified: KAT-T0 (`pk_hash(zeros)`), KAT-T1 (`pk_hash(patterned_te)`), KAT-T2 (`mu(known_mu_pre)`). All assert 64-byte exact match. |
| **Trigger** | `andna_init()` — step 1 of the self-test sequence |
| **Failure behavior** | Module enters Error State; all FFI functions return `AndnaErr::Internal` |
| **Vectors location** | `crates/transcript/src/lib.rs` — hardcoded `KAT_T0_PK_HASH`, `KAT_T1_PK_HASH`, `KAT_T2_MU` byte arrays |
| **Cross-language parity** | Python parity confirmed — `python/tests/test_frame_packer.py` verifies same vectors independently. Note: Python is outside the FIPS cryptographic module boundary and is non-authoritative; parity is informational only. |
| **Regeneration** | `python3 tests/generate_transcript_kats.py --verify` — exits 0 on match, exits 1 on divergence |
| **Status** | **Implemented.** Passes in `cargo test -p andna-ffi` with FIPS features. |

### 4.3 ML-DSA-44 Known Answer Test (KAT)

| Field | Value |
|---|---|
| **Test Type** | Power-Up KAT |
| **Algorithm** | ML-DSA-44 (FIPS 204) |
| **Test Vector Source** | Official NIST ACVP-Server FIPS 204 sigVer vectors (external interface, preHash=pure). Vendored under `crates/mldsa44/tests/vectors/acvp_mldsa44_sigver.json` with SHA-256 manifest and provenance in `crates/mldsa44/tests/vectors/README.md`. Power-up KAT uses tcId 11 (expected-valid case). |
| **Test Operation** | Verify the vendored ACVP signature against its public key and context via `verify_with_ctx_str` (ACCEPT). Verify a one-bit-corrupted signature (REJECT). Assert both outcomes match expected. |
| **Trigger** | `andna_init()` — step 2 of the self-test sequence. Also exercised by the Rust test suite (`cargo test -p andna-mldsa44`), which runs the full vendored vector set. |
| **Failure behavior** | Module enters Error State; all FFI functions return `AndnaErr::Internal` |
| **Tests location** | `crates/mldsa44/` — unit + liboqs roundtrip + ACVP external/pure vector harness (`tests/acvp_sigver.rs`) |
| **ACVP vector tooling** | `tests/download_nist_acvp.py` (fetches + filters external/pure vectors); `tests/extract_kat_for_ffi.py` + `tests/apply_acvp_kat_to_ffi.py` (reproducibility bridge to the embedded FFI KAT) |
| **Status** | **Implemented.** Official NIST ACVP-Server external/pure sigVer vectors vendored and wired into `andna_init()`. Harness passes 10/10. This is NOT an ACVP server test session or CAVP certificate — see Section 6. |

### 4.4 Software Integrity Test

| Field | Value |
|---|---|
| **Test Type** | Power-Up Software Integrity Check |
| **Mechanism** | HMAC-SHA-256 (Path A′) — full-file HMAC of `libandna_ffi.so` against an associated `ANDNA-INTEGRITY-v1` reference file. |
| **Purpose** | Detect unauthorized or accidental modification of the module artifact under the approved build and deployment process |
| **Trigger** | `andna_init()` — step 3 (final) of the self-test sequence under the `fips-integrity-hmac` feature |
| **Path discovery** | Module path supplied via `ANDNA_INTEGRITY_MODULE_PATH`; reference path supplied via `ANDNA_INTEGRITY_REF_PATH`. Both are caller-supplied trusted deployment configuration; see Section 7. |
| **Reference format** | Strict `ANDNA-INTEGRITY-v1` plain-text format with fields: `artifact`, `algorithm`, `key_id`, `key_status`, `tag_hex`, `artifact_sha256`. Generated by `cargo run -p xtask -- write-integrity-reference`. |
| **Verification** | (1) Read module bytes from `ANDNA_INTEGRITY_MODULE_PATH`. (2) Parse reference at `ANDNA_INTEGRITY_REF_PATH`. (3) Compute SHA-256 of module bytes; constant-time compare to `artifact_sha256`. (4) Compute HMAC-SHA-256 of module bytes with embedded integrity key; constant-time compare to `tag_hex`. (5) All comparisons must pass. |
| **Failure behavior** | Module enters Error State; all FFI functions return `AndnaErr::Internal`. Fail-closed conditions: missing env vars, empty env vars, file read failure, reference parse failure, algorithm mismatch, SHA-256 mismatch, HMAC mismatch. |
| **Tests location** | `crates/ffi/src/lib.rs` unit tests + `scripts/smoke_hmac_integrity.py` release-lane smoke test |
| **Status** | **Implemented (Path A′).** Replaces the prior `fips-integrity-stub` placeholder. Validated end-to-end in Docker and on GitHub Actions HostB. |

---

## 5. Algorithm Use Summary

| Algorithm | Standard | Used In | Approved Mode | Self-Test | CAVP Status |
|---|---|---|---|---|---|
| ML-DSA-44 | FIPS 204 | `andna_verify_vnext`, `andna_verify_frame_v2`, `andna_gen_test_frame` (test only) | Yes | KAT wired into `andna_init()` step 2 | TBD (lab) |
| SHAKE256 | FIPS 202 | `andna-transcript` (`pk_hash`, `μ`) called by both verify paths; `liboqs` internal use | Yes | KAT wired into `andna_init()` step 1 | TBD (lab) |
| SHA-3-256 | FIPS 202 | `andna-audit` — audit chain hash only (outside FIPS boundary) | **No** (outside boundary) | N/A | Not applicable |
| HMAC-SHA-256 | FIPS 198-1 | `fips-integrity-hmac` software integrity self-test | Yes | CAST wired into `andna_init()` step 0; primitive used in step 3 | TBD (lab) |
| Stub backend (`andna-mldsa44`) | N/A | CI only — never in Approved Mode artifact | **No** | N/A — excluded | Not applicable |
| `fips-integrity-stub` | N/A | Development only — mutually exclusive with `fips-integrity-hmac` | **No** | N/A — excluded | Not applicable |

> **Python Boundary Note:** Python tooling (`python/andna/`, Replay Engine, test harness) is **outside the FIPS cryptographic module boundary**. Python is non-authoritative and does not provide Approved Mode cryptographic services. Cross-language parity confirmations (e.g., SHAKE256 KAT vectors vs. `hashlib.shake_256`) are informational only.

---

## 6. Open Items Before CST Lab Submission

The following item must be resolved before this inventory is final:

| Item | Owner | Priority | Status |
|---|---|---|---|
| ACVP test session through accredited CST lab (CAVP certificate) | CST lab engagement | **P0 — Blocking submission** | Distinct from vendoring public reference vectors. A CST lab must run an ACVP session against the module to issue CAVP certificates for ML-DSA-44, SHAKE256, and HMAC-SHA-256. Not yet engaged. |
| Record CAVP certificate numbers once issued | Post-lab | Post-submission | Pending lab engagement |

**Closed items** (retained for traceability):

- ~~Wire SHAKE256 KAT into FFI init path~~ — **CLOSED** (v1.2.0). Wired into `andna_init()`.
- ~~Wire ML-DSA-44 KAT into FFI init path~~ — **CLOSED** (v1.2.0). Wired into `andna_init()`.
- ~~Confirm `andna-audit` hash chain does not use SHAKE256 inside boundary~~ — **CLOSED** (v1.1.0). Uses SHA3-256, outside boundary.
- ~~Replace self-generated ML-DSA-44 KAT with official NIST ACVP sigVer vectors~~ — **CLOSED** (v1.3.0). Vendored ACVP external/pure tcId 11 vector.
- ~~Implement software integrity test (replace `fips-integrity-stub`)~~ — **CLOSED** (v1.4.0). HMAC-SHA-256 Path A′ implemented; CAST + full-file integrity check wired into `andna_init()`.

---

## 7. Non-Claims

- This document does not claim CAVP certification for any listed algorithm.
- ACVP testing through an accredited CST laboratory is required before any CAVP
  certificate can be issued.
- `liboqs` 0.10.1 is not independently FIPS-validated. The FIPS validation claim applies
  to the AN-DNA module as a whole, with `liboqs` as the embedded implementation under test.
- **HMAC integrity key (non-secret):** The HMAC-SHA-256 integrity key is a non-secret
  software-integrity test key, embedded in the module. It is not claimed to provide
  secrecy or confidentiality. The integrity check is designed to detect unauthorized or
  accidental modification of the module artifact under the approved build and deployment
  process. It does not provide cryptographic tamper resistance against a fully privileged
  adversary capable of reverse-engineering and modifying both the module binary and its
  associated integrity reference file.
- **Env-var trust boundary:** The software-integrity self-test relies on the runtime
  environment to honestly identify the module file via `ANDNA_INTEGRITY_MODULE_PATH` and
  the associated reference file via `ANDNA_INTEGRITY_REF_PATH`. These environment variables
  are treated as trusted deployment configuration: they are within the trust boundary of
  the operator's deployment but outside the cryptographic module boundary. The module does
  not, and at this validation level cannot, defend against an attacker who has the
  capability to set these environment variables in the operator's process, redirecting
  verification to an unmodified copy of the module while a modified copy is actually loaded.

---

## 8. Revision History

| Version | Date | Change |
|---|---|---|
| 1.0.0 | 2026-03-10 | Initial draft. Two approved algorithms documented. Self-test requirements identified. Three blocking open items noted. |
| 1.1.0 | 2026-03-10 | Closed andna-audit/SHAKE256 open item — confirmed SHA3-256 (not SHAKE256), outside boundary. Updated Section 5 algorithm use summary to include `andna_verify_frame_v2` as a path exercising ML-DSA-44 and SHAKE256. |
| 1.2.0 | 2026-05-25 | Updated Sections 4.2/4.3: SHAKE256 and ML-DSA-44 KATs wired into `andna_init()` power-up self-test path; closed open items. Updated Section 4.1: software integrity labeled STUB/NON-CONFORMANT (`fips-integrity-stub`). Added Sections 2.3 (SHA-3-256, boundary-adjacent), 2.4 (HMAC-SHA-256, planned P0 blocker). Added `fips-integrity-stub` to Section 3 non-approved table. Updated Section 5 algorithm summary. Added Python boundary note. Updated Section 6 open items. |
| 1.3.0 | 2026-05-28 | Section 4.2: replaced self-generated ML-DSA-44 KAT with official NIST ACVP-Server FIPS 204 sigVer vectors (external/pure interface, tcId 11) wired into `andna_init()`; harness 10/10, FFI 12/12. Section 6: closed the "replace self-gen vectors" open item; clarified that a CST-lab ACVP session for the CAVP certificate is a distinct, still-open P0. R1 proof-pack `verification_digest` confirmed stable across local and pinned Docker lanes. HMAC-SHA-256 software integrity remained the sole open engineering P0. |
| 1.4.0 | 2026-05-30 | HMAC-SHA-256 software integrity implemented (Path A′). Section 2.4 updated from "Planned — P0 Blocker" to "Implemented." Section 4 restructured: locked self-test order is `HMAC CAST → SHAKE256 KAT → ML-DSA-44 KAT → software integrity check`; added Section 4.1 (HMAC CAST, RFC 4231 test vector); renumbered SHAKE256 and ML-DSA-44 KATs to 4.2 and 4.3; rewrote Section 4.4 software integrity to describe Path A′ (full-file HMAC against `ANDNA-INTEGRITY-v1` reference file with caller-supplied paths). Section 3 updated: `fips-integrity-stub` reclassified from STUB/NON-CONFORMANT to "development only." Section 5 algorithm summary refreshed. Section 6 P0 list reduced to one open item (CST-lab ACVP session). Section 7 added two new non-claims: non-secret HMAC integrity key, env-var trust boundary. All HMAC integrity work validated end-to-end in Docker and GitHub HostB; Gate 2 `verification_digest` (`85f4dc18...`) confirmed stable. |