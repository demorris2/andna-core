# AN-DNA FIPS 140-3 Algorithm Inventory

**Document:** `/fips/algorithm_inventory.md`
**Status:** Draft — Pre-CST Lab Submission
**Version:** 1.3.0
**Date:** 2026-05-28
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

### 2.3 SHA-3-256

| Field | Value |
|---|---|
| **Algorithm** | SHA-3-256 (Fixed-output hash function) |
| **Standard** | FIPS 202 |
| **Implementer / Crate** | `andna-audit` crate (via `sha3` crate) |
| **Approved Mode Use** | **No — used outside the FIPS cryptographic module boundary** |
| **Use in Module** | Tamper-evident audit chain hash chaining in `andna-audit`. SHA3-256 is distinct from SHAKE256 (XOF); this is a fixed-output hash used for audit log integrity only. |
| **Notes** | `andna-audit` is explicitly outside the FIPS boundary (see `module_boundary.md` Section 3.2). SHA3-256 in the audit chain is not a FIPS-approved service of this module. Listed for completeness per CMVP requirements. |

### 2.4 HMAC-SHA-256 (Planned — P0 Blocker)

| Field | Value |
|---|---|
| **Algorithm** | HMAC-SHA-256 |
| **Standard** | FIPS 198-1 (HMAC) + FIPS 180-4 (SHA-256) |
| **Implementer / Crate** | Planned — `andna-ffi` (`fips-integrity-check` feature, replacing `fips-integrity-stub`) |
| **Approved Mode Use** | Yes — required for software integrity power-up self-test |
| **Use in Module** | Software integrity check: HMAC-SHA-256 digest of `libandna_ffi.so` verified against a reference value at module load. Required by FIPS 140-3 Section 9.1. |
| **CAVP Certificate** | TBD — ACVP testing required at CST lab engagement |
| **Power-Up Self-Test** | This algorithm IS the power-up software integrity test |
| **Status** | **P0 blocker — pending implementation. Currently stubbed via `fips-integrity-stub` (STUB / NON-CONFORMANT).** |

---

## 3. Non-Approved Cryptographic Algorithms (No Security Claim)

These mechanisms are expressly non-approved and are not used in the FIPS Approved Mode
of operation. They are documented here for completeness per CMVP requirements.

| Algorithm / Mechanism | Standard | Implementer / Crate | Approved Mode Use | Notes |
|---|---|---|---|---|
| Stub Backend | N/A | `andna-mldsa44` (`stub` feature) | **No** | Always-pass verification shim used strictly for CI bootstrap during build pipeline testing. Produces no real cryptographic output. Excluded from FIPS boundary and Approved Mode by feature flag. The `oqs-backend` feature must be enabled and `stub` must be absent for any Approved Mode artifact. |
| `fips-integrity-stub` | N/A | `andna-ffi` (`fips-integrity-stub` feature) | **No — STUB / NON-CONFORMANT** | Placeholder software integrity stub. Does not perform real HMAC-SHA-256 binary digest verification. P0 blocker — must be replaced with a real HMAC-SHA-256 implementation before CST lab submission. Must not be present in any Approved Mode artifact. |

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
| **Status** | **STUB / NON-CONFORMANT — `fips-integrity-stub` feature active. P0 blocker: must be replaced with real HMAC-SHA-256 before CST lab submission.** |

### 4.2 ML-DSA-44 Known Answer Test (KAT)

| Field | Value |
|---|---|
| **Test Type** | Conditional / Power-Up KAT |
| **Algorithm** | ML-DSA-44 (FIPS 204) |
| **Test Vector Source** | Official NIST ACVP-Server FIPS 204 sigVer vectors (external interface, preHash=pure). Vendored under `crates/mldsa44/tests/vectors/acvp_mldsa44_sigver.json` with SHA-256 manifest and provenance in `crates/mldsa44/tests/vectors/README.md`. Power-up KAT uses tcId 11 (expected-valid case). |
| **Test Operation** | Verify the vendored ACVP signature against its public key and context via `verify_with_ctx_str` (ACCEPT). Verify a one-bit-corrupted signature (REJECT). Assert both outcomes match expected. |
| **Trigger** | `andna_init()` power-up self-test path. Also exercised by the Rust test suite (`cargo test -p andna-mldsa44`), which runs the full vendored vector set. |
| **Failure behavior** | Module enters error state; all FFI functions return error code |
| **Tests location** | `crates/mldsa44/` — 4 unit + 5 liboqs roundtrip + ACVP external/pure vector harness (`tests/acvp_sigver.rs`) |
| **ACVP vector tooling** | `tests/download_nist_acvp.py` (fetches + filters external/pure vectors); `tests/extract_kat_for_ffi.py` + `tests/apply_acvp_kat_to_ffi.py` (reproducibility bridge to the embedded FFI KAT) |
| **Status** | **Implemented.** Official NIST ACVP-Server external/pure sigVer vectors vendored and wired into `andna_init()`. Harness passes 10/10; `cargo test -p andna-ffi` with FIPS features passes 12/12. This is NOT an ACVP server test session or CAVP certificate — see Section 6. |

### 4.3 SHAKE256 Known Answer Test (KAT)

| Field | Value |
|---|---|
| **Test Type** | Power-Up KAT |
| **Algorithm** | SHAKE256 (FIPS 202) |
| **Test Vector Source** | Internal — generated by `tests/generate_transcript_kats.py`, byte-identical to Python `hashlib.shake_256` reference |
| **Test Operation** | Three fixed-input vectors verified: KAT-T0 (`pk_hash(zeros)`), KAT-T1 (`pk_hash(patterned_te)`), KAT-T2 (`mu(known_mu_pre)`). All assert 64-byte exact match. |
| **Trigger** | `andna_init()` power-up self-test path (wired on `fips/package-v1`). Also exercised by Rust test suite (`cargo test`). |
| **Failure behavior** | Module enters error state; all FFI functions return error code |
| **Vectors location** | `crates/transcript/src/lib.rs` — hardcoded `KAT_T0_PK_HASH`, `KAT_T1_PK_HASH`, `KAT_T2_MU` byte arrays |
| **Cross-language parity** | Python parity confirmed — `python/tests/test_frame_packer.py` verifies same vectors independently. Note: Python is outside the FIPS cryptographic module boundary and is non-authoritative; parity is informational only. |
| **Regeneration** | `python3 tests/generate_transcript_kats.py --verify` — exits 0 on match, exits 1 on divergence |
| **Status** | **Wired into `andna_init()` power-up self-test path. Passes: `cargo test -p andna-ffi` with FIPS features (12/12).** |

---

## 5. Algorithm Use Summary

| Algorithm | Standard | Used In | Approved Mode | Self-Test | CAVP Status |
|---|---|---|---|---|---|
| ML-DSA-44 | FIPS 204 | `andna_verify_vnext`, `andna_verify_frame_v2`, `andna_gen_test_frame` (test only) | Yes | KAT wired into `andna_init()` | TBD (lab) |
| SHAKE256 | FIPS 202 | `andna-transcript` (`pk_hash`, `μ`) called by both verify paths; `liboqs` internal use | Yes | KAT wired into `andna_init()` | TBD (lab) |
| SHA-3-256 | FIPS 202 | `andna-audit` — audit chain hash only (outside FIPS boundary) | **No** (outside boundary) | N/A | Not applicable |
| HMAC-SHA-256 | FIPS 198-1 | Software integrity check (planned — P0 blocker) | Yes (when implemented) | IS the software integrity test | TBD (lab) |
| Stub backend (`andna-mldsa44`) | N/A | CI only — never in Approved Mode artifact | **No** | N/A — excluded | Not applicable |
| `fips-integrity-stub` | N/A | Placeholder integrity check — STUB / NON-CONFORMANT | **No** | N/A — excluded | Not applicable |

> **Python Boundary Note:** Python tooling (`python/andna/`, Replay Engine, test harness) is **outside the FIPS cryptographic module boundary**. Python is non-authoritative and does not provide Approved Mode cryptographic services. Cross-language parity confirmations (e.g., SHAKE256 KAT vectors vs. `hashlib.shake_256`) are informational only.

---

## 6. Open Items Before CST Lab Submission

The following items must be resolved before this inventory is final:

| Item | Owner | Priority | Status |
|---|---|---|---|
| Implement software integrity test (Section 4.1) | Engineering | **P0 — Blocking** | **STUB / NON-CONFORMANT** — `fips-integrity-stub` active. Replace with HMAC-SHA-256 (FIPS 198-1) implementation. |
| ~~Wire SHAKE256 KAT into FFI init path as power-up self-test~~ | Engineering | ~~Blocking~~ | **CLOSED** — wired into `andna_init()` on `fips/package-v1`. Passes 12/12 FIPS feature tests. |
| ~~Wire ML-DSA-44 KAT into FFI init path as power-up self-test~~ | Engineering | ~~Blocking~~ | **CLOSED** — wired into `andna_init()` on `fips/package-v1`. Passes 12/12 FIPS feature tests. |
| ~~Replace self-generated ML-DSA-44 KAT with official NIST ACVP sigVer vectors~~ | Engineering | ~~P0~~ | **CLOSED** — official NIST ACVP-Server external/pure sigVer vectors vendored (`crates/mldsa44/tests/vectors/`) and wired into `andna_init()`. Harness 10/10; FFI 12/12. R1 `verification_digest` confirmed stable across local + Docker lanes. |
| ACVP test session through accredited CST lab (CAVP certificate) | CST lab engagement | **P0 — Blocking submission** | Distinct from vendoring public reference vectors. A CST lab must run an ACVP session against the module to issue a CAVP certificate. Not yet engaged. |
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
| 1.2.0 | 2026-05-25 | Updated Sections 4.2/4.3: SHAKE256 and ML-DSA-44 KATs wired into `andna_init()` power-up self-test path on `fips/package-v1`; closed open items. Updated Section 4.1: software integrity labeled STUB/NON-CONFORMANT (`fips-integrity-stub`). Added Sections 2.3 (SHA-3-256, boundary-adjacent), 2.4 (HMAC-SHA-256, planned P0 blocker). Added `fips-integrity-stub` to Section 3 non-approved table. Updated Section 5 algorithm summary. Added Python boundary note. Updated Section 6 open items to reflect current status. |
| 1.3.0 | 2026-05-28 | Section 4.2: replaced self-generated ML-DSA-44 KAT with official NIST ACVP-Server FIPS 204 sigVer vectors (external/pure interface, tcId 11) wired into `andna_init()`; harness 10/10, FFI 12/12. Section 6: closed the "replace self-gen vectors" open item; clarified that a CST-lab ACVP session for the CAVP certificate is a distinct, still-open P0. R1 proof-pack `verification_digest` confirmed stable across local (rustc 1.92.0) and pinned Docker (rustc 1.76.0) lanes. HMAC-SHA-256 software integrity remains the sole open engineering P0. |
