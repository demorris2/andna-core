# AN-DNA FIPS 140-3 Module Boundary Definition

**Document:** `/fips/module_boundary.md`
**Status:** Draft — Pre-CST Lab Submission
**Version:** 1.1.0
**Date:** 2026-03-10
**Prepared by:** Darrell Morris Jr. — ArcNeura

---

## 1. Module Identity

| Field | Value |
|---|---|
| **Module Name** | AN-DNA Core Verification Library |
| **Module Version** | 1.0.0 |
| **Embodiment** | Software Cryptographic Module |
| **FIPS Target** | FIPS 140-3 Level 1 |
| **Primary Artifact** | `libandna_ffi.so` (Linux shared library) / `libandna_ffi.a` (static archive) |
| **Programming Language** | Rust (2021 edition) |
| **Public Interface** | C ABI — exported FFI surface defined in `andna-ffi/src/lib.rs` |
| **C Header** | `include/andna_core.h` (cbindgen-generated; see Section 8.2) |

---

## 2. Cryptographic Module Boundary

The FIPS logical boundary is the Rust shared library produced by the `andna-ffi` crate and its internal dependencies. The boundary encompasses **only** the compiled Rust cryptographic module — defined precisely by the crates listed in Section 3.1.

The boundary is enforced at the C ABI: all interactions with the module occur through the exported FFI functions defined in `andna-ffi/src/lib.rs`. No caller above the C ABI boundary is within scope.

The crate dependency graph within the boundary is:

```
andna-ffi  (boundary surface — sole unsafe crate)
    ├── andna-core       (verify_vnext / verify_frame_v2 orchestrator)
    │     ├── andna-codec       (zero-alloc frame parser)
    │     ├── andna-transcript  (SHAKE256 pk_hash + μ derivation)
    │     ├── andna-mldsa44     (ML-DSA-44 verify engine)
    │     └── andna-contracts   (compile-time constants + assertions)
    ├── andna-codec       (also called directly for andna_parse_mu_pre_header)
    ├── andna-contracts   (constants shared across boundary surface)
    └── andna-audit       (AuditSink — see Section 3.2 note)
```

---

## 3. Crate Inventory

### 3.1 Inside the Boundary (Included)

These crates are compiled into `libandna_ffi.so` and are within the FIPS logical boundary. All cryptographic operations occur exclusively within this set.

| Crate | Role | Notes |
|---|---|---|
| `andna-ffi` | FFI entry point — exports all C ABI functions | Sole `unsafe` crate in the workspace. All external calls enter here. `ffi_guard` (catch_unwind) ensures no Rust panic propagates across the boundary. |
| `andna-core` | Verification orchestrator | Implements `verify_vnext()` and `verify_frame_v2()`. Sequences: frame parse → pk_hash binding check → μ derivation → ML-DSA-44 verify. Called directly by `andna-ffi`. |
| `andna-codec` | Strict zero-allocation frame parser/packer | Parses and validates Frame v2 (4030 bytes) and mu_pre (274 bytes). Called by `andna-core` and directly by `andna-ffi` for `andna_parse_mu_pre_header`. No cryptographic operations — pure structural validation and canonical encoding. |
| `andna-transcript` | SHAKE256 derivation | Computes `pk_hash = SHAKE256(T_E, 64)` and `μ = SHAKE256(mu_pre, 64)`. Constant-time output comparison. Contains the three authoritative SHAKE256 KAT vectors (KAT-T0, KAT-T1, KAT-T2). |
| `andna-mldsa44` | ML-DSA-44 verify engine | Wraps `liboqs` ML-DSA-44 verify via `oqs-sys`. Must be compiled with `oqs-backend` feature. The `stub` feature is an always-pass CI shim — prohibited in Approved Mode. Includes the vendored NIST ACVP-Server external/pure sigVer vector harness (`tests/acvp_sigver.rs`) — 10/10 vectors passing. |
| `andna-contracts` | Compile-time constants and assertions | Single source of truth for all protocol constants. 25+ compile-time `assert!` guards enforce invariants at build time. Generates `include/andna_vnext_contracts.h` with `_Static_assert` guards for C consumers. No cryptographic operations. |
| `liboqs` 0.10.1 (vendored C) | ML-DSA-44 and SHAKE256 primitives | C library compiled from source at version 0.10.1 with `-DOQS_DIST_BUILD=ON`. Linked statically into the Rust module. Within boundary. Not independently FIPS-validated — under test as part of this module. |

### 3.2 Outside the Boundary (Excluded)

These components are explicitly excluded from the FIPS logical boundary. No security claims apply to them.

| Component | Reason for Exclusion |
|---|---|
| `andna-audit` / AuditSink | Deterministic tamper-evident logging infrastructure. Hash chaining uses SHA3-256 for audit integrity, not as a FIPS-approved cryptographic service. Logging is not a cryptographic operation within the module boundary. See note below. |
| Python CLI / `python/andna/` package | Non-cryptographic orchestration layer. Calls the module via ctypes FFI but is not compiled into it. |
| `python/andna/contracts.py` | Constants mirror with 20+ import-time assertions. Consistency enforcement tooling, not cryptographic operations. |
| Replay Engine CLI (`python -m andna verify/replay/export`) | Verification and audit tooling built on top of the module. Not within it. |
| `xtask` crate | Build-time tooling: C header regeneration and drift detection CI gate. Not compiled into the module artifact. See Section 8.2. |
| `contracts_codegen` crate | Generates `include/andna_vnext_contracts.h` from `andna-contracts`. Build-time tooling only. |
| `ffi_cli` | CLI smoke-test tool. Not compiled into `libandna_ffi.so`. |
| FastAPI / REST layer | Optional network interface. Not compiled into the module. |
| Demo scripts and integration tooling | Not part of the module under test. |
| AIPMP | Internal product management tooling. Not part of the module under test. |
| `stub` feature of `andna-mldsa44` | Always-pass CI bootstrap shim. Explicitly non-approved. Produces no real cryptographic output. Prohibited in Approved Mode builds. |
| `fips-integrity-stub` feature of `andna-ffi` | **Development only.** Software-integrity shim that always passes — used for fast iteration in non-release builds. Mutually exclusive with `fips-integrity-hmac` (enforced by crate-root `compile_error!` gates). Prohibited in any Approved Mode artifact. The real software-integrity mechanism is HMAC-SHA-256 (Path A′), wired under the `fips-integrity-hmac` feature; see Section 9 and `fips/algorithm_inventory.md` Section 4.4. |

> **Python Boundary Note:** Python tooling (`python/andna/`, Replay Engine CLI, FastAPI layer) is **outside the FIPS cryptographic module boundary**. Python is non-authoritative and does not provide Approved Mode cryptographic services. The Python layer calls the module via ctypes FFI but is not compiled into it. No FIPS security claim applies to any Python component.

> **Note on `andna-audit` and Audit Chain Boundary:** The AuditSink is called from within `andna_verify_frame_v2` at the FFI boundary, after the cryptographic verification result is determined. The audit append occurs after the crypto decision is complete; the AuditSink does not influence or participate in the cryptographic computation. The SHA3-256 hash chaining in the audit log serves audit integrity for the R1 Proof Pack, not FIPS-approved cryptographic services. Audit chain boundary recommendation: the SHA3-256 chain hash computation and the validator (`validate_jsonl`) are in-boundary only insofar as they are compiled into the Rust workspace — they are logically outside the FIPS cryptographic module boundary. JSONL serialization and all file I/O are out-of-boundary. The CST lab examiner should note that `andna_audit_export_jsonl` is listed in Section 4 for completeness of the FFI surface; no FIPS security claim is made for it.

---

## 4. Public Interfaces (Exported FFI Surface)

The following functions constitute the complete public interface of the cryptographic module. All are exported with C linkage from `andna-ffi/src/lib.rs`. All return `AndnaErr` — a `#[repr(C)]` enum with ABI-stable integer values (see Section 4.1). The C header `include/andna_core.h` is generated by `cbindgen` and is the authoritative source for C consumers.

| Export | Signature | FIPS Role | Description |
|---|---|---|---|
| `andna_init` | `() -> AndnaErr` | **Module Initialization** | Power-up self-test gate. Gates all cryptographic entry points through the Rust module state machine (Uninitialized → Approved / Error). Runs the locked self-test sequence: HMAC-SHA-256 CAST → SHAKE256 KAT → ML-DSA-44 KAT (vendored NIST ACVP external/pure tcId 11) → software integrity check (HMAC-SHA-256, Path A′; see `fips/algorithm_inventory.md` Section 4.4). Returns `Ok` on success; `Internal` on any failure. |
| `andna_verify_vnext` | `(mu_pre: *const u8, mu_pre_len: usize, te: *const u8, te_len: usize, sig: *const u8, sig_len: usize) -> AndnaErr` | Cryptographic | Decomposed verifier. Accepts mu_pre (274 bytes), T_E (1336 bytes), and signature (2420 bytes) separately. Validates ML-DSA-44 transcript. Primary approved cryptographic service. |
| `andna_verify_frame_v2` | `(frame: *const u8, frame_len: usize) -> AndnaErr` | Cryptographic | Packed Frame v2 verifier (4030 bytes = mu_pre \|\| T_E \|\| sig). Primary operational path. Calls `andna-core::verify_frame_v2` then appends one record to the AuditSink (boundary-excluded). |
| `andna_parse_mu_pre_header` | `(mu_pre: *const u8, mu_pre_len: usize, out_device_id32: *mut u8, out_epoch: *mut u64, out_sid: *mut u8) -> AndnaErr` | Non-cryptographic | Fast-path header parser via `andna-codec`. Extracts `device_id32`, `epoch`, and `sid` from mu_pre for pre-crypto gating. No cryptographic operations. |
| `andna_gen_test_frame` | `(out_ptr: *mut u8, out_len: usize) -> AndnaErr` | Test service | Generates a complete self-consistent 4030-byte Frame v2 (keygen → mu_pre construction → sign → pack). For KAT and integration testing only. Must not be used in production authentication flows. |
| `andna_audit_export_jsonl` | `(path: *const c_char) -> AndnaErr` | **Outside boundary** | Exports AuditSink log as deterministic JSONL to the specified path. AuditSink is excluded from the FIPS boundary. No FIPS security claim applies to this function. Listed for completeness of the FFI surface. |
| `andna_strerror` | `(err: AndnaErr) -> *const c_char` | Status output | Returns a static, NUL-terminated human-readable string for the given `AndnaErr` code. Cannot panic. No cryptographic operations. |
| `andna_version` | `() -> *const c_char` | Status output | Returns the module version string (NUL-terminated, static lifetime). Cannot panic. Used for software integrity verification reference. |

### 4.1 AndnaErr Enum (ABI-Stable — Integer Values Are Frozen)

| Variant | Value | Meaning |
|---|---|---|
| `Ok` | 0 | Operation succeeded |
| `Length` | 1 | Input length mismatch or null pointer |
| `MuPre` | 2 | mu_pre buffer malformed |
| `Te` | 3 | T_E buffer malformed |
| `Sig` | 4 | Signature buffer malformed |
| `PkHashMismatch` | 5 | pk_hash binding check failed |
| `SigInvalid` | 6 | ML-DSA-44 signature verification failed |
| `EpochMismatch` | 7 | mu_pre.epoch ≠ T_E.epoch (Security Directive B) |
| `DeviceIdMismatch` | 8 | device_id32 ≠ SHAKE256(device_id16, 32) (Security Directive E) |
| `Internal` | 100 | Caught panic, self-test failure, mutex poisoned, or module not initialized |

> Integer values 0–8 and 100 are frozen per ABI stability contract (`R1_FEATURE_FREEZE.md`). New variants may be added with values > 100 in future versions without breaking ABI.

---

## 5. Protocol Constants (Authoritative — From `andna-contracts`)

These values are enforced at compile time via `assert!` macros in `andna-contracts` and at the C ABI level via `_Static_assert` guards in `include/andna_vnext_contracts.h`. Any change requires a full boundary revision, new validated artifact, and ADR per `R1_FEATURE_FREEZE.md`.

| Constant | Value | Description |
|---|---|---|
| `MU_PRE_LEN` | 274 bytes | Canonical fixed-width authentication payload buffer |
| `TE_LEN` | 1336 bytes | Epoch Public Key: ρ(32) + t₁(1280) + epoch(8) + id16(16) |
| `SIG_LEN` | 2420 bytes | ML-DSA-44 signature: z(2304) + h(84) + c̃(32) |
| `FRAME_V2_LEN` | 4030 bytes | Packed frame: mu_pre + T_E + sig |
| `PK_HASH_LEN` | 64 bytes | SHAKE256 output length for pk_hash and μ derivation |
| `DOMAIN_SEP` | `ANDNAAUTH` | 9 bytes ASCII, no NUL terminator (hex: `41 4E 44 4E 41 41 55 54 48`) |
| `VERSION_BYTE` | `0x01` | mu_pre version field at byte offset 73 |

---

## 6. External Dependencies Inside the Boundary

| Dependency | Version | Type | Source |
|---|---|---|---|
| `liboqs` | 0.10.1 | C library (vendored, built from source) | Open Quantum Safe project |
| `oqs-sys` | pinned in `Cargo.lock` | Rust FFI bindings to liboqs | Cargo registry |
| `sha3` | pinned in `Cargo.lock` | SHAKE256 XOF implementation used by `andna-transcript` | Cargo registry |
| `zeroize` | pinned in `Cargo.lock` | Secure memory zeroization of intermediate buffers | Cargo registry |

> All versions are pinned in `Cargo.lock`. The lock file must not be regenerated between the module build and CST lab submission. The `rust-toolchain.toml` file pins the Rust compiler version independently.

---

## 7. Approved Mode Boundary Statement

The module operates in **Approved Mode** when and only when all of the following conditions hold:

1. The artifact is compiled from the exact source commit and toolchain defined in `/fips/build_manifest.json`.
2. The `andna-mldsa44` crate is compiled with the `oqs-backend` feature flag enabled. The `stub` feature must not be present in any Approved Mode build.
3. The Gate 1 bundle — both `libandna_ffi.so` and `libandna_ffi.integrity` — matches the SHA-256 values recorded in `fips/gate1_golden.md` Section 2. Both files must ship together; the runtime software-integrity self-test requires both. See Section 8.3 for the distinct R1 Proof Pack audit chain anchor.
4. The module is loaded in one of the Operational Environments defined in `/fips/operational_environments.md`.
5. `andna_init()` has been called and returned `AndnaErr::Ok`, confirming all power-up self-tests completed successfully before any cryptographic output was produced.

Any deviation from these conditions places the module outside Approved Mode. The module's behavior outside Approved Mode carries no FIPS security claim.

---

## 8. Design Assurance

### 8.1 Constant Enforcement Across Language Boundaries

Protocol constants are defined once in `andna-contracts` and enforced independently at three layers:

| Layer | Mechanism | Effect |
|---|---|---|
| Rust compile time | 25+ `assert!` macros in `andna-contracts` | Build fails on any constant divergence |
| C ABI | `_Static_assert` guards in `include/andna_vnext_contracts.h` (generated by `contracts_codegen`) | C consumer compilation fails on constant divergence |
| Python import time | 20+ `assert` statements in `python/andna/contracts.py` | Python `ImportError` on constant divergence at startup |

A protocol constant change cannot silently propagate — it will produce a build failure, C compilation failure, or Python import failure at the earliest possible detection point.

### 8.2 C Header Integrity (cbindgen + xtask Drift Detection)

The public C header `include/andna_core.h` is generated by `cbindgen` from `andna-ffi/src/lib.rs`. It is not hand-maintained.

The `xtask` crate provides two commands enforced as CI gates:

| Command | Purpose | CI Gate |
|---|---|---|
| `cargo run -p xtask -- gen-headers` | Regenerates `andna_core.h` and `andna_vnext_contracts.h` from source | Run on header changes |
| `cargo run -p xtask -- check-drift` | Fails if generated headers differ from committed headers | Runs on every PR |

A passing `check-drift` result is evidence that committed C headers accurately reflect the Rust source at the time of the build. This constitutes automated configuration management for the C ABI surface and is directly relevant to FIPS 140-3 design assurance requirements.

### 8.3 Parity Anchors — Distinct Digests, Distinct Claims

Two digests appear in AN-DNA documentation. They are distinct artifacts with distinct purposes and must not be conflated:

| Anchor | Digest | Artifact | Algorithm | Purpose |
|---|---|---|---|---|
| Gate 1 Bundle | See `fips/gate1_golden.md` Section 2 (two SHA-256 hashes — `libandna_ffi.so` and `libandna_ffi.integrity`) | Two-artifact bundle (`libandna_ffi.so` + `libandna_ffi.integrity`) | SHA-256 | **FIPS Approved Mode condition.** Proves deterministic cross-host binary reproducibility for the full bundle. Anchors the module identity, including the runtime integrity reference. |
| R1 Proof Pack Anchor | `85f4dc18777bc2122cf671dce6c2d69d92c80b5d0dbd78a83a644afa1159818d` | `manifest.json` → `verification_digest` | SHA3-256 | **Gate 2 procurement evidence.** Proves deterministic audit chain output across Host A and Host B for the fixture verification session. Not a module binary hash. Outside FIPS boundary. |

The Gate 1 Golden Hash is the FIPS-relevant value. The R1 Proof Pack Anchor is a procurement evidence artifact for the `andna_audit.jsonl` chain and is outside the FIPS boundary.

### 8.4 Memory Safety Boundary

The module is implemented in safe Rust throughout, with one precisely bounded exception: `andna-ffi/src/lib.rs` is the sole `unsafe` crate in the workspace by design. The memory safety boundary is defined as the Rust FFI / `liboqs` C interface inside `andna-mldsa44`.

Key safety properties enforced at the boundary:

- `ffi_guard` (catch_unwind) in `andna-ffi` catches all Rust panics before they can unwind across the C ABI — which would be undefined behavior.
- Null pointer checks occur before `catch_unwind` on every function that accepts pointer arguments.
- Intermediate cryptographic buffers are zeroized on drop via the `zeroize` crate.
- No heap ownership crosses the FFI boundary. All inputs are caller-owned; the module copies into local buffers before operating on them.

---

## 9. Module State Machine

The module implements a three-state finite state machine enforced by an `AtomicI32` in `andna-ffi/src/init.rs`.

| State | Integer | Description | Entry Condition |
|---|---|---|---|
| **Uninitialized** | 0 | Module loaded; `andna_init()` not yet called. All cryptographic FFI functions return `AndnaErr::Internal`. | Initial state on library load. |
| **Approved** | 1 | All power-up self-tests passed. Full cryptographic services available. | `andna_init()` called and all KATs + integrity check returned pass. |
| **Error** | -1 | Self-test failure or runtime integrity failure. All cryptographic FFI functions return `AndnaErr::Internal`. Module must be reloaded to exit. | Any self-test in `andna_init()` fails. |

State transitions:
- **Uninitialized → Approved:** `andna_init()` called; SHAKE256 KAT passes; ML-DSA-44 KAT passes; software integrity check passes (currently stubbed — P0 blocker).
- **Uninitialized → Error:** Any self-test in `andna_init()` fails.
- **Approved → Error:** Reserved for runtime integrity failure (future use).
- **Error → Uninitialized:** Module unload and reload only.

### 9.1 Cryptographic Services and Module Entry Points

The following services are available **only in Approved state**:

| Entry Point | Service |
|---|---|
| `andna_verify_vnext()` | ML-DSA-44 transcript verification (decomposed) |
| `andna_verify_frame_v2()` | ML-DSA-44 transcript verification (packed frame) |
| `andna_parse_mu_pre_header()` | mu_pre header parsing (non-cryptographic fast path) |
| `andna_gen_test_frame()` | Test frame generation (ML-DSA-44 keygen + sign) |

The following services are available in **all states** (informational, no cryptographic output):

| Entry Point | Service |
|---|---|
| `andna_init()` | Module initialization / state transition |
| `andna_strerror()` | Error string query |
| `andna_version()` | Version string query |
| `andna_audit_export_jsonl()` | Audit log export (boundary-excluded) |

---

## 10. P0 Blockers Before CST Lab Submission

The following items are **blocking** for FIPS 140-3 submission. No other changes are required to the module architecture before lab engagement.

| # | Item | Status |
|---|---|---|
| 1 | CST-lab ACVP test session and CAVP certificates for ML-DSA-44, SHAKE256, and HMAC-SHA-256 | Pending lab engagement |

**Closed engineering items** (retained for traceability):

- ~~P0-1: Software integrity check~~ — **CLOSED** (v1.3.0). Implemented as HMAC-SHA-256 Path A′ on `fips/hmac-integrity`. Full-file HMAC of `libandna_ffi.so` against an associated `ANDNA-INTEGRITY-v1` reference file with caller-supplied paths. Replaces the prior `fips-integrity-stub` placeholder. Validated end-to-end in Docker and on GitHub Actions HostB.
- ~~P0-2: ML-DSA-44 KAT vectors~~ — **CLOSED** (v1.3.0). Replaced self-generated vectors with the official NIST ACVP-Server external/pure sigVer vector set (tcId 11 as the power-up KAT case). The SHAKE256 KAT vectors remain internally generated as documented in `fips/algorithm_inventory.md` Section 4.2; ACVP AFT confirmation is part of the CST-lab session above.

---

## 11. Non-Claims

This document does not claim:

- FIPS 140-3 validation. Validation requires testing by an accredited CST laboratory under a CMVP contract.
- CAVP certification for ML-DSA-44 or SHAKE256. ACVP testing through the CST lab is required before any CAVP certificate can be issued.
- That `liboqs` 0.10.1 is independently FIPS-validated. It is not. The FIPS validation claim applies to the AN-DNA module as a whole, with `liboqs` as the embedded implementation under test.
- Security claims for `andna-audit`, the Replay Engine, the Python layer, or any other component outside the boundary defined in Section 3.1.
- **HMAC integrity key (non-secret).** The HMAC-SHA-256 integrity key used by the software-integrity self-test (Section 4 / `fips/algorithm_inventory.md` Section 4.4) is a non-secret software-integrity test key, embedded in the module. It is not claimed to provide secrecy or confidentiality. The integrity check is designed to detect unauthorized or accidental modification of the module artifact under the approved build and deployment process. It does not provide cryptographic tamper resistance against a fully privileged adversary capable of reverse-engineering and modifying both the module binary and its associated integrity reference file.

- **Env-var trust boundary.** The software-integrity self-test relies on the runtime environment to honestly identify the module file via `ANDNA_INTEGRITY_MODULE_PATH` and the associated reference file via `ANDNA_INTEGRITY_REF_PATH`. These environment variables are treated as trusted deployment configuration: they are within the trust boundary of the operator's deployment but outside the cryptographic module boundary. The module does not, and at this validation level cannot, defend against an attacker who has the capability to set these environment variables in the operator's process, redirecting verification to an unmodified copy of the module while a modified copy is actually loaded.

---

## 12. Revision History

| Version | Date | Change |
|---|---|---|
| 1.0.0 | 2026-03-10 | Initial draft. Gate 1 build parameters incorporated. Three-function FFI surface (speculative). |
| 1.1.0 | 2026-03-10 | Full boundary pass from source inspection of `andna-ffi/src/lib.rs` and R1 artifacts. Added `andna-core` and `andna-codec` to Section 3.1 (two previously missing crates). Added `xtask`, `contracts_codegen`, `ffi_cli` to Section 3.2. Added Section 5 (protocol constants with authoritative TE_LEN=1336). Added Section 8 (design assurance: three-layer constant enforcement, cbindgen/xtask drift detection, parity anchor disambiguation, memory safety boundary detail). Updated Section 4 to reflect complete 8-function FFI surface (7 implemented + andna_init specified). Added AndnaErr enum table. Corrected return type from i32 to AndnaErr throughout. |
| 1.2.0 | 2026-05-25 | Updated Section 4: `andna_init()` is implemented on `fips/package-v1`; SHAKE256 and ML-DSA-44 KATs wired into power-up self-test path; STUB/NON-CONFORMANT label added for `fips-integrity-stub`. Corrected TE_LEN to 1336 (matches `TE_V1_LEN` compile-time assertion in `andna-contracts`; prior value was wrong). Removed erroneous "+2 reserved" from TE_LEN breakdown. Added Python boundary note. Refined audit chain boundary statement. Added Section 9 (State Machine + Cryptographic Services), Section 10 (P0 Blockers). Renumbered Non-Claims to Section 11. |
| 1.3.0 | 2026-05-30 | Updated to reflect post-HMAC-integrity state. Section 3.1: `andna-mldsa44` row updated to describe the vendored NIST ACVP external/pure harness (10/10) rather than self-generated tests. Section 3.2: `fips-integrity-stub` reclassified from STUB/NON-CONFORMANT to "development only," with cross-reference to the real `fips-integrity-hmac` mechanism. Section 4: `andna_init` description rewritten to describe the locked self-test sequence (HMAC CAST → SHAKE256 → ML-DSA-44 → software integrity). Section 7 Approved Mode condition #3 updated: now references the two-artifact Gate 1 bundle via `fips/gate1_golden.md` rather than the dead `231778...` hash. Section 8.3 Parity Anchors table: Gate 1 entry rewritten as a bundle anchor pointing at `gate1_golden.md` Section 2. Section 10 P0 Blockers: both engineering items closed; only the CST-lab ACVP session remains. Section 11: added two new non-claims (non-secret HMAC integrity key, env-var trust boundary). |
