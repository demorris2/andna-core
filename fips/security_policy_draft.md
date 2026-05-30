# Non-Proprietary Security Policy
## AN-DNA Core Verification Library
### Version 1.0.0

**Vendor:** ArcNeura
**Prepared by:** Darrell Morris Jr.
**Document Version:** 1.0.0 (Draft — Pre-CST Lab Submission)
**Date:** 2026-03-10
**FIPS Target:** FIPS 140-3 Security Level 1
**CMVP Status:** Pre-validation — not yet submitted

> This is a Non-Proprietary Security Policy prepared in accordance with
> NIST SP 800-140B Rev. 1. It is intended for public release upon
> CMVP certificate issuance. All information herein is non-proprietary.
> Proprietary implementation details are excluded.

---

## Table of Contents

1. Cryptographic Module Specification
2. Cryptographic Module Ports and Interfaces
3. Roles, Services, and Authentication
4. Software / Firmware Security
5. Operational Environment
6. Cryptographic Key Management
7. Self-Tests
8. Design Assurance
9. Mitigation of Other Attacks
10. Security Rules
11. Non-Claims and Scope Limitations
12. Glossary
13. References

---

## 1. Cryptographic Module Specification

### 1.1 Module Identification

| Field | Value |
|---|---|
| **Module Name** | AN-DNA Core Verification Library |
| **Module Version** | 1.0.0 |
| **Vendor** | ArcNeura |
| **Embodiment** | Software Cryptographic Module |
| **FIPS 140-3 Security Level** | Level 1 |
| **Primary Artifact** | `libandna_ffi.so` (Linux shared library) / `libandna_ffi.a` (static archive) |
| **Programming Language** | Rust (2021 edition) |
| **Public Interface** | C ABI — exported FFI surface |

### 1.2 Module Description

The AN-DNA Core Verification Library is a post-quantum cryptographic software
module implementing ML-DSA-44 (FIPS 204) signature verification and SHAKE256
(FIPS 202) hash derivation. The module provides the cryptographic verification
engine for the AN-DNA True vNext device authentication protocol.

The module's primary function is to verify ML-DSA-44 proof transcripts
produced by the Fiat-Shamir with Aborts (FSwA) prover loop on AN-DNA
devices. The verifier holds only the Epoch Public Key T_E and the
canonical 274-byte payload (mu_pre); it holds no device secret material.
This public-verifier architecture eliminates the centralized trust
vulnerabilities of shared-secret verifier models.

### 1.3 Cryptographic Module Boundary

The physical and logical boundary of the module is the compiled Rust
shared library `libandna_ffi.so` / `libandna_ffi.a`. The boundary
encompasses the following crates compiled into the artifact:

| Component | Role |
|---|---|
| `andna-ffi` | FFI entry point — C ABI exports (sole `unsafe` crate) |
| `andna-core` | Verification orchestrator — sequences parse → pk_hash → μ → verify |
| `andna-codec` | Zero-allocation frame and mu_pre parser/packer |
| `andna-mldsa44` | ML-DSA-44 verify engine |
| `andna-transcript` | SHAKE256 pk_hash and μ derivation |
| `andna-contracts` | Shared compile-time cryptographic constants |
| `liboqs` 0.10.1 | Embedded ML-DSA-44 and SHAKE256 primitives (C, built from source) |

The following components are explicitly **outside** the module boundary
and carry no FIPS security claim:

- Python CLI wrapper and test harness
- FastAPI / REST interface layer
- Demo scripts and integration tooling
- AuditSink / Replay Engine (deterministic logging infrastructure)
- The `stub` feature of `andna-mldsa44` (CI bootstrap shim — non-approved)
- The `fips-integrity-stub` feature of `andna-ffi` — development-only software-integrity shim that always passes. Mutually exclusive with `fips-integrity-hmac` (enforced by crate-root `compile_error!` gates). Prohibited in any Approved Mode artifact.

> **Python Boundary Note:** Python tooling is **outside the FIPS cryptographic module boundary**. It is non-authoritative and does not provide Approved Mode cryptographic services. The Python layer calls the module via ctypes FFI but is not compiled into it.

### 1.4 Approved Mode Indicator

The module operates in **Approved Mode** when and only when:

1. The artifact is compiled with the `oqs-backend` feature flag. The
   `stub` feature must be absent.
2. The two-artifact Gate 1 bundle (`libandna_ffi.so` and the associated
   `libandna_ffi.integrity` reference file) matches the recorded values
   in `fips/gate1_golden.md` Section 2.
3. The module is loaded in a defined Operational Environment
   (see Section 5).
4. All power-up self-tests complete successfully before any output
   is produced (see Section 7).

---

## 2. Cryptographic Module Ports and Interfaces

Per FIPS 140-3, software module interfaces are defined as logical
ports rather than physical connectors.

| FIPS 140-3 Interface | Implementation |
|---|---|
| **Data Input** | Byte buffers (`mu_pre`, `T_E`, `sig`, or packed `frame`) passed to verification functions via C ABI |
| **Data Output** | `AndnaErr` return code from all FFI functions; JSONL audit log written by `andna_audit_export_jsonl` |
| **Control Input** | Function call invocation from the calling process via C ABI |
| **Status Output** | `AndnaErr` return code; `andna_strerror()` human-readable string; module state (Pre-Init / Approved / Error) |
| **Power** | Provided by the host operating system process |

### 2.1 Exported FFI Functions (Complete Public Interface)

All functions return `AndnaErr` (a C-compatible `#[repr(C)]` enum with ABI-stable integer values) unless otherwise noted. The `ffi_guard` wrapper ensures no Rust panic propagates across the FFI boundary; panics are caught and returned as `AndnaErr::Internal` (value 100).

| Function | Signature | FIPS Service | Description |
|---|---|---|---|
| `andna_init` | `() -> AndnaErr` | Module Initialization | **Required first call.** Implemented on `fips/package-v1`; gates all cryptographic entry points through the Rust module state machine. HMAC-SHA-256 CAST, SHAKE256 transcript KAT, ML-DSA-44 KAT, and HMAC-SHA-256 software integrity check (Path A′) are wired into the power-up self-test path in the locked order: CAST → SHAKE256 → ML-DSA-44 → software integrity. Returns `Ok` on success; `Internal` on any self-test failure. No cryptographic function may be called before `andna_init` returns `Ok`. |
| `andna_verify_vnext` | `(mu_pre: *const u8, mu_pre_len: usize, te: *const u8, te_len: usize, sig: *const u8, sig_len: usize) -> AndnaErr` | Proof Verification | Decomposed verifier. Accepts mu_pre (274 bytes), T_E, and signature separately. Validates ML-DSA-44 transcript. Returns `Ok` (ACCEPT) or a specific reject code. |
| `andna_verify_frame_v2` | `(frame: *const u8, frame_len: usize) -> AndnaErr` | Proof Verification (packed) | Primary operational path. Accepts packed 4030-byte Frame v2 (mu_pre \|\| T_E \|\| sig). Runs verification and appends one record to the Rust-owned AuditSink. |
| `andna_parse_mu_pre_header` | `(mu_pre: *const u8, mu_pre_len: usize, out_device_id32: *mut u8, out_epoch: *mut u64, out_sid: *mut u8) -> AndnaErr` | Header Parsing | Pre-crypto fast-path parser. Extracts `device_id32`, `epoch`, and `sid` from mu_pre for gating logic before committing to full verification. No cryptographic operations. |
| `andna_gen_test_frame` | `(out_ptr: *mut u8, out_len: usize) -> AndnaErr` | Test Frame Generation | Generates a complete, self-consistent 4030-byte Frame v2 (keygen → mu_pre construction → sign → pack). For KAT and integration testing only. Must not be used in production authentication flows. |
| `andna_audit_export_jsonl` | `(path: *const c_char) -> AndnaErr` | Audit Export | Exports the Rust-owned AuditSink log as deterministic JSONL to the specified path. Not a cryptographic operation. Boundary-excluded component (AuditSink) surfaces here; no FIPS security claim applies to this function. |
| `andna_strerror` | `(err: AndnaErr) -> *const c_char` | Status Output | Returns a static, NUL-terminated human-readable string for the given error code. Cannot panic. |
| `andna_version` | `() -> *const c_char` | Version Query | Returns the module version string (NUL-terminated, static lifetime). Used for software integrity verification. Cannot panic. |

#### AndnaErr Enum Values (ABI-Stable)

| Value | Integer | Meaning |
|---|---|---|
| `Ok` | 0 | Operation succeeded |
| `Length` | 1 | Input length mismatch or null pointer |
| `MuPre` | 2 | mu_pre buffer malformed |
| `Te` | 3 | T_E buffer malformed |
| `Sig` | 4 | Signature buffer malformed |
| `PkHashMismatch` | 5 | pk_hash binding check failed |
| `SigInvalid` | 6 | ML-DSA-44 signature verification failed |
| `EpochMismatch` | 7 | mu_pre.epoch ≠ T_E.epoch |
| `DeviceIdMismatch` | 8 | device_id32 ≠ SHAKE256(device_id16, 32) |
| `Internal` | 100 | Caught panic or internal error (including: self-test failure, module not initialized, mutex poisoned) |

> **Note on `andna_audit_export_jsonl`:** This function exposes the AuditSink,
> which is explicitly outside the FIPS module boundary (see Section 1.3 and
> `/fips/module_boundary.md` Section 3.2). It is listed here for completeness
> as part of the complete public FFI surface. No FIPS security claim is made
> for this function.

---

## 3. Roles, Services, and Authentication

### 3.1 Roles

The module supports two logical roles per FIPS 140-3:

| Role | Description |
|---|---|
| **Cryptographic Officer (CO)** | Responsible for module installation, configuration verification, and ensuring the Approved Mode conditions in Section 1.4 are met. Verifies the Golden Hash before deployment. |
| **User** | Any process or service that calls the module's exported FFI functions to perform verification operations. |

The module does not support a Maintenance role. Role-based
authentication is not required at FIPS 140-3 Level 1.

### 3.2 Services

| Service | Role | Description | Algorithms Used |
|---|---|---|---|
| Module Initialization | CO / User | Invokes `andna_init()`. Runs all power-up self-tests. Transitions module to Approved Mode on success; Error State on any failure. | ML-DSA-44 KAT, SHAKE256 KAT, Software Integrity |
| Proof Verification (decomposed) | User | Invokes `andna_verify_vnext()`. Validates ML-DSA-44 transcript from separate mu_pre, T_E, and sig buffers. | ML-DSA-44 (FIPS 204), SHAKE256 (FIPS 202) |
| Proof Verification (packed) | User | Invokes `andna_verify_frame_v2()`. Validates packed 4030-byte Frame v2. Appends audit record to AuditSink after each call. Primary operational path. | ML-DSA-44 (FIPS 204), SHAKE256 (FIPS 202) |
| Header Parsing | User | Invokes `andna_parse_mu_pre_header()`. Extracts gating fields from mu_pre before full verification. | None (parsing only) |
| Test Frame Generation | User | Invokes `andna_gen_test_frame()`. Generates a self-consistent signed frame for testing. Not for production use. | ML-DSA-44 (FIPS 204) |
| Audit Export | CO / User | Invokes `andna_audit_export_jsonl()`. Exports deterministic JSONL audit log to a file path. No cryptographic operations. Outside FIPS boundary. | None |
| Error String Query | CO / User | Invokes `andna_strerror()`. Returns human-readable error description for a given `AndnaErr` code. | None (informational) |
| Version Query | CO / User | Invokes `andna_version()`. Returns module version string for integrity verification. | None (informational) |
| Show Status | CO | Inspect return code of `andna_init()` to confirm module is in Approved Mode. | None (status output) |

### 3.3 Authentication

FIPS 140-3 Level 1 does not require operator authentication. The
module relies on the host operating system's process isolation and
access controls to restrict access to the module's services.

---

## 4. Software / Firmware Security

### 4.1 Software Integrity

The module implements a software integrity check as part of the
power-up self-test sequence (see Section 7.1). This check verifies
that the module binary has not been modified since the validated
build was produced.

The integrity check mechanism will be implemented as a digest
verification of `libandna_ffi.so` against a known-good reference
value embedded in or associated with the module.

### 4.2 Finite State Model

The module operates in one of three states:

| State | Description | Transitions |
|---|---|---|
| **Pre-Init** | Module loaded, `andna_init()` not yet called. No cryptographic output permitted. | → Approved Mode (self-tests pass) / → Error State (self-tests fail) |
| **Approved Mode** | All self-tests passed. `andna_verify_vnext()`, `andna_verify_frame_v2()`, `andna_parse_mu_pre_header()`, and `andna_gen_test_frame()` services are available. | → Error State (runtime integrity failure) |
| **Error State** | Self-test failure or runtime integrity failure. All functions return error code. Module must be reloaded to exit this state. | → Pre-Init (module reload) |

### 4.3 Memory Safety

The module is implemented in Rust, which provides memory safety
guarantees at the language level — no buffer overflows, no
use-after-free, and no null pointer dereferences within safe Rust
code. The boundary between safe Rust and the embedded `liboqs` C
library is explicitly marked `unsafe` at the FFI call sites in
`andna-mldsa44` and is the defined memory safety boundary for
the module.

Intermediate cryptographic buffers (masking vectors, commitment
polynomials) are zeroized via the `zeroize` crate upon drop,
preventing residual secret material in heap or stack memory.

---

## 5. Operational Environment

The module is validated in the following Tested Operational
Environment. Full details are in `/fips/operational_environments.md`.

### 5.1 Tested Operational Environment (OE-1)

| Field | Value |
|---|---|
| **Operating System** | Ubuntu 22.04 LTS (Jammy Jellyfish) |
| **Platform** | General Purpose Computer (GPC) |
| **Processor** | Intel Xeon (x86_64) |
| **Hypervisor** | None — bare-metal / standard cloud compute |
| **Modifiable Environment** | Yes |

OE-1 is anchored to the Gate 1 cross-platform verification
result: an ephemeral Ubuntu 22.04 instance on GitHub Actions
produced the exact Golden Hash independently of the local
development environment.

### 5.2 Vendor Affirmed Environments

The vendor affirms correct operation, without additional CST lab
testing, on the following environments. Only OE-1 appears on the
CMVP certificate.

| OE | Environment |
|---|---|
| OE-2 | Windows 11 (x86_64) |
| OE-3 | Red Hat Enterprise Linux 9 (x86_64) |
| OE-4 | Ubuntu 24.04 LTS (x86_64) |

---

## 6. Cryptographic Key Management

### 6.1 Cryptographic Keys and Parameters

| Item | Type | Location | Lifetime | Protection |
|---|---|---|---|---|
| Epoch Public Key (T_E) | Public parameter | Passed in via `frame` input buffer | Single verification session | No protection required — public |
| ML-DSA-44 KAT reference keypair | Test-only static value | Hardcoded in module KAT harness | Module lifetime (read-only) | Not a secret — fixed test vector |
| SHAKE256 KAT reference vectors | Test-only static values | Hardcoded in `andna-transcript` | Module lifetime (read-only) | Not a secret — fixed test vector |

### 6.2 Key Generation

The module does not generate keys for production authentication use.
Key generation (`andna_gen_test_frame`) is provided for testing
purposes only and must not be used in production authentication flows.
Production ML-DSA-44 keypairs for devices are generated outside the
module boundary, on the device prover side.

### 6.3 Key Zeroization

The module does not hold persistent secret key material during normal
operation. Intermediate computational buffers are zeroized after use
via the `zeroize` crate. The module does not implement explicit key
entry or key output services at FIPS 140-3 Level 1.

---

## 7. Self-Tests

The module performs the following self-tests. All self-tests are
triggered by the `andna_init()` call and must complete successfully
before any cryptographic output is produced.

### 7.1 Power-Up Self-Tests

#### 7.1.1 Software Integrity Test

| Field | Value |
|---|---|
| **Purpose** | Detect unauthorized modification of the module binary |
| **Mechanism** | HMAC-SHA-256 (FIPS 198-1) of `libandna_ffi.so` verified against the `tag_hex` field of an associated `ANDNA-INTEGRITY-v1` reference file. The reference file additionally records `artifact_sha256`, which is verified before the HMAC comparison. Path discovery via `ANDNA_INTEGRITY_MODULE_PATH` and `ANDNA_INTEGRITY_REF_PATH` environment variables (trusted deployment configuration — see Section 11). |
| **Failure action** | Module enters Error State; all FFI functions return `AndnaErr::Internal` |
| **Implementation status** | **Implemented (Path A′).** Validated end-to-end in Docker and on GitHub Actions HostB. Smoke test covers valid pair (rc=0), missing env (rc=100), tampered module (rc=100), tampered reference (rc=100). |

#### 7.1.2 ML-DSA-44 Known Answer Test (KAT)

| Field | Value |
|---|---|
| **Purpose** | Verify correct operation of the ML-DSA-44 signature verification primitive |
| **Test type** | sigVer KAT — fixed keypair, fixed message, fixed signature |
| **Vectors** | Official NIST ACVP-Server FIPS 204 sigVer vectors (external interface, preHash=pure), vendored under `crates/mldsa44/tests/vectors/`. Power-up KAT uses tcId 11 (expected-valid case). Harness passes 10/10. |
| **Pass condition** | Valid signature: ACCEPT. Corrupted signature (one bit flipped): REJECT. |
| **Failure action** | Module enters Error State; all FFI functions return error code |
| **Implementation status** | **Implemented.** Vendored official NIST ACVP-Server external/pure sigVer vectors are wired into `andna_init()`. The full vendored set passes 10/10; FFI test suite passes with FIPS features. |

#### 7.1.3 SHAKE256 Known Answer Test (KAT)

| Field | Value |
|---|---|
| **Purpose** | Verify correct operation of the SHAKE256 extendable-output function |
| **Test type** | Three fixed-input vectors: KAT-T0 (pk_hash, zero input), KAT-T1 (pk_hash, patterned T_E), KAT-T2 (mu derivation from known mu_pre) |
| **Vectors** | Hardcoded in `crates/transcript/src/lib.rs`. Cross-language parity confirmed against Python `hashlib.shake_256`. Regenerated via `python3 tests/generate_transcript_kats.py --verify` |
| **Pass condition** | All three 64-byte output vectors match hardcoded reference values exactly |
| **Failure action** | Module enters Error State; all FFI functions return error code |
| **Implementation status** | **Wired into `andna_init()` power-up self-test path on `fips/package-v1`. Passes in `cargo test -p andna-ffi` with FIPS features (12/12).** |

### 7.2 Conditional Self-Tests

The module does not perform conditional self-tests at FIPS 140-3
Level 1 beyond the power-up tests listed above. If `andna_gen_test_frame`
is invoked, it implicitly exercises the ML-DSA-44 sign and verify
paths, but this does not constitute a FIPS conditional self-test.

### 7.3 Self-Test Failure Handling

If any power-up self-test fails, the module transitions to the
Error State. In the Error State:

- `andna_verify_vnext()` returns `AndnaErr::Internal` on all calls
- `andna_verify_frame_v2()` returns `AndnaErr::Internal` on all calls
- `andna_parse_mu_pre_header()` returns `AndnaErr::Internal` on all calls
- `andna_gen_test_frame()` returns `AndnaErr::Internal` on all calls
- `andna_strerror()` and `andna_version()` continue to function (informational, cannot panic)
- `andna_audit_export_jsonl()` continues to function (not a cryptographic service)
- The module must be unloaded and reloaded to attempt re-initialization

The Error State is non-recoverable without a reload to prevent
a partially initialized module from producing cryptographic output.

---

## 8. Design Assurance

### 8.1 Configuration Management

All module source code, build scripts, and dependency pins are
maintained under Git version control. The `Cargo.lock` file is
committed to the repository and pins all transitive Rust
dependencies. The `rust-toolchain.toml` pins the Rust compiler
version. The Dockerfile pins the base OS image by digest.

### 8.2 Reproducible Build Verification (Gate 1)

The module implements a verifiable deterministic build process. The build
is independently executed on local Windows + Docker Desktop and on GitHub
Actions HostB (ephemeral Ubuntu), producing a byte-identical two-artifact
bundle:

| Field | Value |
|---|---|
| **Rust Toolchain** | 1.93.1 |
| **liboqs Version** | 0.10.1 |
| **Base OS Image** | `debian:bookworm-slim` (pinned by digest `debian@sha256:74d56e3931e0d5a1dd51f8c8a2466d21de84a271cd3b5a733b803aa91abf4421`) |
| **Build Flags** | `-DOQS_BUILD_ONLY_LIB=ON`, `-DOQS_DIST_BUILD=ON`, `-ffile-prefix-map=/tmp/liboqs=. -ffile-prefix-map=/build=.`, `SOURCE_DATE_EPOCH=1772150400` |
| **FIPS Feature Set** | `oqs-backend fips-integrity-hmac fips-kat-vectors-embedded` |
| **Gate 1 Bundle** | See `fips/gate1_golden.md` Section 2 for current hashes (two artifacts: `libandna_ffi.so` and `libandna_ffi.integrity`). |
| **Verification** | `.github/workflows/hostb_rust_proof.yml` produces the bundle and records both hashes in `build-hashes.txt` |
| **Host A** | Windows + Docker Desktop (local development) |
| **Host B** | Ephemeral Ubuntu — GitHub Actions (remote CI) |
| **Result** | Exact match — byte-identical bundle across both hosts |

Full details, including line-endings hygiene and the engineering history
of the cross-host result, are in `fips/gate1_golden.md` and
`fips/build_manifest.json`.

### 8.3 Guidance Documentation

The following documents constitute the complete guidance package
for this module:

| Document | Contents |
|---|---|
| `/fips/module_boundary.md` | Cryptographic module boundary definition |
| `/fips/build_manifest.json` | Versioned build environment and artifact hashes |
| `/fips/operational_environments.md` | Tested and vendor-affirmed OEs |
| `/fips/algorithm_inventory.md` | FIPS-approved algorithm inventory and self-test status |
| `/fips/security_policy_draft.md` | This document |

---

## 9. Mitigation of Other Attacks

### 9.1 Side-Channel Attack Posture

The module's FSwA rejection sampling loop accumulates all abort
conditions via constant-time bitwise operations into an `abort_flag`
before any branch decision. This prevents intra-iteration timing
leaks — an observer may determine how many iterations occurred
(retry-count leakage, explicitly accepted per the True vNext
architecture) but cannot determine which specific bound caused
an abort.

The `dudect` side-channel harness and Welch's t-test timing leak
prevention is specified in the CI pipeline (`/fips/algorithm_inventory.md`
Section 6). FIPS 140-3 Level 1 does not require formal side-channel
mitigation, but this is documented as a design property of the module.

### 9.2 Denial-of-Service Mitigations

The verifier implements an O(1) fail-fast pipeline that executes
format and norm checks before allocating resources for lattice
matrix expansion. Malformed frames are rejected at minimal cost.
The Redis-based SID replay cache and monotonic epoch guard operate
outside the module boundary (in the calling application layer) and
are not part of the FIPS security claim.

### 9.3 Attacks Not Claimed as Mitigated at Level 1

FIPS 140-3 Level 1 does not require mitigation of physical attacks,
electromagnetic side-channels, or fault injection. No claims are
made for these attack classes.

---

## 10. Security Rules

The following rules must be observed to maintain the module in
Approved Mode. Violation of any rule places the module outside
the scope of the FIPS validation.

1. **`andna_init()` must be called first.** No other exported
   function may be invoked before `andna_init()` returns `0`.

2. **The `oqs-backend` feature must be compiled in.** The `stub`
   feature must not be present in any Approved Mode artifact.

3. **The Gate 1 bundle must be verified before deployment.**
   Both `libandna_ffi.so` and `libandna_ffi.integrity` must be confirmed
   to match the SHA-256 values recorded in `fips/gate1_golden.md`
   Section 2 before the module is placed in service. Both files must
   ship together; the runtime integrity check requires both.

4. **The module must be operated in a defined OE.** Deployment
   outside OE-1 through OE-4 is not covered by the validation.

5. **The Rust toolchain and build flags must not be changed**
   without producing a new validated artifact under the change
   control process. Any change to Rust version, liboqs version,
   or build flags requires a full rebuild and Golden Hash
   re-verification.

6. **`andna_gen_test_frame()` must not be used in production
   authentication flows.** It is a test service only.

7. **The module must transition to Error State on any self-test
   failure.** The calling application must not suppress or ignore
   non-zero return codes from `andna_init()`.

8. **The `stub` feature artifact must never be deployed in any
   environment where FIPS compliance is required.** The `stub`
   backend produces no real cryptographic output and carries no
   security claim.

---

## 11. Non-Claims and Scope Limitations

This document and the associated FIPS package do not claim:

- **FIPS 140-3 validation.** This document is a pre-submission
  draft. Validation requires testing by an accredited Cryptographic
  and Security Testing (CST) laboratory under a CMVP contract.

- - **CAVP certification** for ML-DSA-44, SHAKE256, or HMAC-SHA-256.
  ACVP testing through an accredited CST laboratory is required
  before any CAVP certificate can be issued. The module's power-up
  ML-DSA-44 KAT already uses vendored NIST ACVP-Server external/pure
  sigVer vectors (tcId 11), but vendoring public reference vectors is
  distinct from completing an ACVP test session through the lab.

- **Independent FIPS validation of `liboqs`.** The `liboqs` 0.10.1
  library is not independently FIPS-validated. The FIPS validation
  claim applies to the AN-DNA module as a whole, with `liboqs` as
  the embedded implementation under test.

- **Security claims for components outside the module boundary.**
  The Python wrapper, FastAPI layer, AuditSink, and all other
  excluded components carry no FIPS security claim.

- **Security claims for the `stub` feature artifact** under any
  circumstances.

  - **HMAC integrity key (non-secret).** The HMAC-SHA-256 integrity key is
  a non-secret software-integrity test key, embedded in the module. It is
  not claimed to provide secrecy or confidentiality. The integrity check
  is designed to detect unauthorized or accidental modification of the
  module artifact under the approved build and deployment process. It
  does not provide cryptographic tamper resistance against a fully
  privileged adversary capable of reverse-engineering and modifying both
  the module binary and its associated integrity reference file.

- **Env-var trust boundary.** The software-integrity self-test relies on
  the runtime environment to honestly identify the module file via
  `ANDNA_INTEGRITY_MODULE_PATH` and the associated reference file via
  `ANDNA_INTEGRITY_REF_PATH`. These environment variables are treated as
  trusted deployment configuration: they are within the trust boundary
  of the operator's deployment but outside the cryptographic module
  boundary. The module does not, and at this validation level cannot,
  defend against an attacker who has the capability to set these
  environment variables in the operator's process, redirecting
  verification to an unmodified copy of the module while a modified copy
  is actually loaded.

---

## 12. Glossary

| Term | Definition |
|---|---|
| **ACVP** | Automated Cryptographic Validation Protocol — NIST's system for algorithm testing |
| **Approved Mode** | Operating state in which the module uses only FIPS-approved algorithms and all self-tests have passed |
| **C ABI** | C Application Binary Interface — the calling convention used by the module's exported FFI functions |
| **CAVP** | Cryptographic Algorithm Validation Program |
| **CMVP** | Cryptographic Module Validation Program |
| **CO** | Cryptographic Officer — the role responsible for module configuration and integrity verification |
| **CST** | Cryptographic and Security Testing laboratory — NIST-accredited lab that performs FIPS testing |
| **FFI** | Foreign Function Interface — the mechanism by which non-Rust code calls into the Rust module |
| **FSwA** | Fiat-Shamir with Aborts — the zero-knowledge proof framework used by ML-DSA-44 |
| **Golden Hash** | The SHA-256 digest of the validated `libandna_ffi.so` artifact produced by the deterministic Gate 1 build |
| **KAT** | Known Answer Test — a self-test using fixed inputs and expected outputs |
| **liboqs** | Open Quantum Safe library — the embedded C implementation of ML-DSA-44 and SHAKE256 |
| **ML-DSA-44** | Module-Lattice-Based Digital Signature Algorithm, parameter set 44 (FIPS 204, NIST Category 2) |
| **mu_pre** | The canonical 274-byte fixed-width authentication payload buffer |
| **OE** | Operational Environment |
| **SHAKE256** | SHA-3 Extendable-Output Function with 256-bit security strength (FIPS 202) |
| **T_E** | Epoch Public Key — the tuple (rho, t1, E, DeviceID) held by the stateless verifier |

---

## 13. References

| Reference | Title |
|---|---|
| FIPS 140-3 | Security Requirements for Cryptographic Modules (2019) |
| FIPS 202 | SHA-3 Standard: Permutation-Based Hash and Extendable-Output Functions (2015) |
| FIPS 204 | Module-Lattice-Based Digital Signature Standard (ML-DSA / Dilithium) (2024) |
| NIST SP 800-140 | FIPS 140-3 Derived Test Requirements |
| NIST SP 800-140B Rev. 1 | CMVP Security Policy Requirements: FIPS 140-3 Level 1-3 |
| NIST SP 800-140C | CMVP Approved Security Functions |
| NIST SP 800-218 | Secure Software Development Framework (SSDF) |
| gate1_hostB_report.json | AN-DNA Gate 1 Cross-Platform Build Verification Report (2026-03-03) ||
| /fips/module_boundary.md | AN-DNA Module Boundary Definition v1.0.0 |
| /fips/build_manifest.json | AN-DNA Build Manifest v1.0.0 |
| /fips/operational_environments.md | AN-DNA Operational Environments v1.0.0 |
| /fips/algorithm_inventory.md | AN-DNA Algorithm Inventory v1.0.0 |

---

## Open Items Before CST Lab Submission

| # | Item | Status |
|---|---|---|
| 1 | CST-lab ACVP test session and CAVP certificates for ML-DSA-44, SHAKE256, and HMAC-SHA-256 | Pending lab engagement |

**Closed engineering items** (retained for traceability):

- ~~P0-1: Software integrity check~~ — **CLOSED** (v1.2.0). Implemented as HMAC-SHA-256 Path A′ on `fips/hmac-integrity`. Replaces the prior `fips-integrity-stub` placeholder.
- ~~P0-2: ML-DSA-44 KAT vectors~~ — **CLOSED** (v1.2.0). Replaced self-generated vectors with official NIST ACVP-Server external/pure sigVer vectors (tcId 11).

---

## Revision History

| Version | Date | Change |
|---|---|---|
| 1.0.0 | 2026-03-10 | Initial draft. All five FIPS package documents complete. Three blocking items identified: `andna_init()` implementation, KAT wiring into FFI init path, software integrity test. |
| 1.1.0 | 2026-05-25 | Updated Section 2.1: `andna_init()` implemented on `fips/package-v1`; SHAKE256 and ML-DSA-44 KATs wired into power-up self-test path; software integrity labeled STUB/NON-CONFORMANT. Updated Section 7.1 self-test status. Added Python boundary note to Section 1.3. Added `fips-integrity-stub` exclusion. Added P0 Blockers section. |
| 1.2.0 | 2026-05-30 | Updated to reflect post-HMAC-integrity state. Section 1.4: Approved Mode condition #2 now references the two-artifact Gate 1 bundle via `fips/gate1_golden.md` rather than the dead `231778...` hash. Section 2.1: `andna_init` description updated with the locked self-test order (HMAC CAST → SHAKE256 → ML-DSA-44 → software integrity). Section 7.1.1: software integrity status flipped from STUB/NON-CONFORMANT to Implemented (Path A′); mechanism row describes the `ANDNA-INTEGRITY-v1` reference file and env-var path discovery. Section 7.1.2: ML-DSA-44 KAT vectors row updated to reflect vendored NIST ACVP-Server vectors. Section 8.2: Gate 1 details refreshed to current state (1.93.1, current build flags, two-artifact bundle, `hostb_rust_proof.yml` workflow); dead references to `build_environment.md` and `gate1_hostB_report.json` removed. Section 9 rule #3: updated to reference the bundle via `gate1_golden.md`. Section 11: added two new non-claims (non-secret HMAC integrity key, env-var trust boundary). P0 Blockers section: both engineering items closed; only the CST-lab ACVP session remains. |
