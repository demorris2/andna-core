# AN-DNA FIPS 140-3 Algorithm Inventory

**Document:** `/fips/algorithm_inventory.md`
**Status:** Draft — Pre-CST Lab Submission
**Version:** 1.0.0
**Date:** 2026-03-10
**Prepared by:** Darrell Morris Jr. — ArcNeura
**Reference:** FIPS 140-3, FIPS 202, FIPS 204, NIST SP 800-140C (CMVP Approved
Security Functions)

---

## 1. Overview

This document enumerates every cryptographic algorithm used within the AN-DNA Core
Verification Library boundary. CMVP examiners require a complete and accurate algorithm
inventory — any algorithm used but not listed, or listed but lacking a self-test, will halt
validation.

Two FIPS-approved algorithms are used within the boundary. One non-approved mechanism
(the stub backend) is explicitly documented and excluded from Approved Mode operation.

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

---

## 3. Non-Approved Cryptographic Algorithms (No Security Claim)

These mechanisms are expressly non-approved and are not used in the FIPS Approved Mode
of operation. They are documented here for completeness per CMVP requirements.

| Algorithm / Mechanism | Standard | Implementer / Crate | Approved Mode Use | Notes |
|---|---|---|---|---|
| Stub Backend | N/A | `andna-mldsa44` (`stub` feature) | **No** | Always-pass verification shim used strictly for CI bootstrap during build pipeline testing. Produces no real cryptographic output. Excluded from FIPS boundary and Approved Mode by feature flag. The `oqs-backend` feature must be enabled and `stub` must be absent for any Approved Mode artifact. |

---

## 4. Cryptographic Self-Tests

To comply with FIPS 140-3, the module performs the following self-tests upon initialization
(power-up) before any FFI output is permitted. If any self-test fails, the module must enter
an error state and return a failure code on all subsequent FFI calls until reloaded.

### 4.1 Software Integrity Test

| Field | Value |
|---|---|
| **Test Type** | Software Integrity Check |
| **Mechanism** | HMAC-SHA-256 or equivalent digest verification of `libandna_ffi.so` at load time |
| **Purpose** | Detect corruption or unauthorized modification of the module binary |
| **Trigger** | Module load (before first FFI call) |
| **Failure behavior** | Module enters error state; all FFI functions return error code |
| **Status** | **Required — not yet implemented.** Must be added before CST lab submission. |

### 4.2 ML-DSA-44 Known Answer Test (KAT)

| Field | Value |
|---|---|
| **Test Type** | Conditional / Power-Up KAT |
| **Algorithm** | ML-DSA-44 (FIPS 204) |
| **Test Vector Source** | Internal ACVP self-gen — `tests/generate_acvp_vectors.py` (requires liboqs-python); 6 ACVP self-gen tests in `andna-mldsa44` crate |
| **Test Operation** | Sign a fixed message with a fixed keypair; verify the produced signature (ACCEPT). Verify a corrupted signature (REJECT). Assert both outcomes match expected. |
| **Trigger** | Currently: Rust test suite (`cargo test -p andna-mldsa44`). **Required addition:** promote to module load / power-up init path before first FFI output. |
| **Failure behavior** | Module enters error state; all FFI functions return error code |
| **Tests location** | `crates/mldsa44/` — 4 unit + 5 liboqs roundtrip + 6 ACVP self-gen tests |
| **ACVP vector generator** | `tests/generate_acvp_vectors.py` — generates sigVer vectors from liboqs-python |
| **Status** | **Substantially built — 6 ACVP self-gen tests passing. Remaining work: (1) obtain fixed NIST ACVP sigVer vectors from CST lab for submission (self-gen vectors are not the same as NIST-issued vectors), (2) wire into FFI init path as power-up self-test.** |

### 4.3 SHAKE256 Known Answer Test (KAT)

| Field | Value |
|---|---|
| **Test Type** | Power-Up KAT |
| **Algorithm** | SHAKE256 (FIPS 202) |
| **Test Vector Source** | Internal — generated by `tests/generate_transcript_kats.py`, byte-identical to Python `hashlib.shake_256` reference |
| **Test Operation** | Three fixed-input vectors verified: KAT-T0 (`pk_hash(zeros)`), KAT-T1 (`pk_hash(patterned_te)`), KAT-T2 (`mu(known_mu_pre)`). All assert 64-byte exact match. |
| **Trigger** | Currently: Rust test suite (`cargo test`). **Required addition:** promote to module load / power-up init path before first FFI output. |
| **Failure behavior** | Module enters error state; all FFI functions return error code |
| **Vectors location** | `crates/transcript/src/lib.rs` — hardcoded `KAT_T0_PK_HASH`, `KAT_T1_PK_HASH`, `KAT_T2_MU` byte arrays |
| **Cross-language parity** | Python parity confirmed — `python/tests/test_frame_packer.py` verifies same vectors independently |
| **Regeneration** | `python3 tests/generate_transcript_kats.py --verify` — exits 0 on match, exits 1 on divergence |
| **Status** | **Vectors implemented and verified. Remaining work: wire into FFI init path as power-up self-test (not currently called at module load).** |

---

## 5. Algorithm Use Summary

| Algorithm | Standard | Used In | Approved Mode | Self-Test | CAVP Status |
|---|---|---|---|---|---|
| ML-DSA-44 | FIPS 204 | `andna_verify_vnext`, `andna_verify_frame_v2`, `andna_gen_test_frame` (test only) | Yes | KAT required | TBD (lab) |
| SHAKE256 | FIPS 202 | `andna-transcript` (`pk_hash`, `μ`) called by both verify paths; `liboqs` internal use | Yes | KAT required | TBD (lab) |
| Stub backend | N/A | CI only — never in Approved Mode artifact | **No** | N/A — excluded | Not applicable |

---

## 6. Open Items Before CST Lab Submission

The following items must be resolved before this inventory is final:

| Item | Owner | Priority | Status |
|---|---|---|---|
| Implement software integrity test (Section 4.1) | Engineering | **Blocking** | Not started |
| Wire SHAKE256 KAT into FFI init path as power-up self-test | Engineering | **Blocking** | Vectors exist — integration only |
| Wire ML-DSA-44 KAT into FFI init path as power-up self-test | Engineering | **Blocking** | Tests exist — integration only |
| Obtain fixed NIST ACVP sigVer vectors for ML-DSA-44 from CST lab | CST lab engagement | High | Self-gen vectors exist; NIST-issued vectors required for submission |
| ~~Confirm `andna-audit` hash chain does not use SHAKE256 inside boundary~~ | Engineering | ~~High~~ | **CLOSED — confirmed.** `andna-audit` uses `sha3-256` (fixed-output hash, FIPS 202) for the tamper-evident chain, not SHAKE256 (XOF). SHA3-256 is a distinct algorithm from SHAKE256. The audit chain operates entirely outside the FIPS boundary. No boundary impact. |
| Record CAVP certificate numbers once issued | Post-lab | Post-submission | Pending lab engagement |

---

## 7. Non-Claims

- This document does not claim CAVP certification for any listed algorithm.
- ACVP testing through an accredited CST laboratory is required before any CAVP
  certificate can be issued.
- `liboqs` 0.10.1 is not independently FIPS-validated. The FIPS validation claim applies
  to the AN-DNA module as a whole, with `liboqs` as the embedded implementation under test.

---

## 8. Revision History

| Version | Date | Change |
|---|---|---|
| 1.0.0 | 2026-03-10 | Initial draft. Two approved algorithms documented. Self-test requirements identified. Three blocking open items noted. |
| 1.1.0 | 2026-03-10 | Closed andna-audit/SHAKE256 open item — confirmed SHA3-256 (not SHAKE256), outside boundary. Updated Section 5 algorithm use summary to include `andna_verify_frame_v2` as a path exercising ML-DSA-44 and SHAKE256. |
