# andna-core

Rust workspace implementing the AN-DNA vNext Phase 1 core verification library.
ML-DSA-44 (FIPS 204) post-quantum authentication with C ABI + Python FFI integration.

## Architecture

```
andna-core/
  crates/
    contracts/         # THE LAW — constants, offsets, compile-time assertions
    codec/             # Strict frame parsing/packing, zero-allocation
    transcript/        # SHAKE256 pk_hash + μ derivation (constant-time)
    mldsa44/           # ML-DSA-44 verify engine (liboqs backend)
    core/              # verify_vnext() orchestrator
    ffi/               # C ABI shim (only unsafe lives here)
  contracts_codegen/   # Generates include/andna_vnext_contracts.h
  ffi_cli/             # CLI smoke test tool for FFI
  xtask/               # Header regeneration, drift detection, integrity reference generator
  include/
    andna_vnext_contracts.h  # Generated C constants with _Static_assert guards
    andna_core.h             # C ABI header (cbindgen-generated)
  python/
    andna/                   # Python package
      contracts.py           # Constants mirror (20+ import-time assertions)
      native.py              # ctypes FFI bindings to libandna_ffi.so
      engine.py              # VERIFY_ENGINE feature flag router
      frame_packer.py        # mu_pre builder, frame pack/unpack
    tests/                   # Python test suite
  tests/
    generate_transcript_kats.py  # SHAKE256 KAT vector generator
    download_nist_acvp.py        # Fetches + filters NIST ACVP external/pure sigVer vectors
    extract_kat_for_ffi.py       # Bridges a vendored ACVP vector into the embedded FFI KAT
    apply_acvp_kat_to_ffi.py     # Applies the extracted KAT to the FFI constants
```

## Hard Contracts (Non-Negotiable)

| Constant       | Value | Notes                                    |
|----------------|-------|------------------------------------------|
| MU_PRE_LEN     | 274   | domain_sep = "ANDNAAUTH" (9 bytes)       |
| TE_V1_LEN      | 1336  | ρ(32) + t₁(1280) + epoch(8) + id16(16)  |
| TE_V2_LEN      | 1352  | Defined, NOT enabled (Phase 2+)          |
| SIG_LEN        | 2420  | z(2304) + h(84) + c̃(32)                 |
| FRAME_V2_LEN   | 4030  | mu_pre + T_E + sig                       |
| DOMAIN_SEP     | `ANDNAAUTH` | 9 bytes, hex 41 4E 44 4E 41 41 55 54 48 |

## Features

The crypto backend is controlled via Cargo features, propagated through the crate graph:

```
andna-ffi → andna-core → andna-mldsa44
  ↓            ↓              ↓
oqs-backend  oqs-backend   oqs-backend (default: real ML-DSA-44 via liboqs)
stub         stub           stub        (always-pass for CI bootstrap)
```

The `andna-ffi` crate additionally has two mutually-exclusive software-integrity
modes (a crate-root `compile_error!` enforces that exactly one is selected):

```
fips-integrity-stub   development only — always-pass integrity shim
fips-integrity-hmac   real HMAC-SHA-256 full-file integrity check (Path A′)
```

The FIPS / release lane uses `fips-integrity-hmac`. See `fips/algorithm_inventory.md`
Section 4.4 for the integrity mechanism and `fips/security_policy_draft.md` for the
trust-boundary scope.

```bash
# Build with real ML-DSA-44 (requires liboqs installed)
cargo build --release -p andna-ffi             # default = oqs-backend

# Build with stub (no liboqs required)
cargo build --release -p andna-ffi --no-default-features --features stub
```

## Prerequisites

**For real ML-DSA-44 (oqs-backend):**
```bash
# Install liboqs from source
sudo apt-get install cmake ninja-build
git clone --depth 1 --branch 0.10.1 https://github.com/open-quantum-safe/liboqs.git /tmp/liboqs
cd /tmp/liboqs && mkdir build && cd build
cmake -GNinja -DBUILD_SHARED_LIBS=ON -DCMAKE_INSTALL_PREFIX=/usr/local ..
ninja && sudo ninja install && sudo ldconfig
```

**For stub mode:** No external dependencies.

## Quick Start

```bash
# Run all Rust tests (with liboqs)
LD_LIBRARY_PATH=/usr/local/lib cargo test --all

# Run ACVP sigVer tests specifically
LD_LIBRARY_PATH=/usr/local/lib cargo test -p andna-mldsa44 --test acvp_sigver -- --nocapture

# Run with stub backend (no liboqs needed)
cargo test -p andna-mldsa44 --no-default-features --features stub
cargo test -p andna-core --no-default-features --features stub

# Build release (produces libandna_ffi.a + libandna_ffi.so)
LD_LIBRARY_PATH=/usr/local/lib cargo build --release -p andna-ffi

# Generate the HMAC integrity reference (FIPS release lane)
cargo build -p andna-ffi --release --features "oqs-backend fips-integrity-hmac fips-kat-vectors-embedded"
cargo run -p xtask -- write-integrity-reference \
  target/release/libandna_ffi.so \
  target/release/libandna_ffi.integrity

# FFI smoke test
LD_LIBRARY_PATH=/usr/local/lib cargo run -p ffi-cli -- smoke

# Regenerate C headers
cargo run -p xtask -- gen-headers

# Check for header drift (CI gate)
cargo run -p xtask -- check-drift

# Python tests
cd python
pip install pytest
VERIFY_ENGINE=python python -m pytest tests/ -v
VERIFY_ENGINE=rust ANDNA_LIB_PATH=../target/release/libandna_ffi.so python -m pytest tests/ -v
```

## Rust API

```rust
use andna_core::{verify_vnext, verify_frame_v2, VerifyError};
use andna_contracts::*;

// Component-level verify
let result = verify_vnext(&mu_pre, &te, &sig);

// Frame-level verify (4030 bytes)
let result = verify_frame_v2(&frame);
```

## C API

```c
#include "andna_core.h"

AndnaErr r = andna_verify_frame_v2(frame, 4030);
if (r != ANDNA_ERR_OK) {
    printf("rejected: %s\n", andna_strerror(r));
}
```

## Python API

```python
from andna.engine import get_engine

engine = get_engine()  # reads VERIFY_ENGINE env var (python|rust)
result = engine.verify_frame_v2(frame_bytes)
if not result.ok:
    log.warning("verify failed: %s", result.error_msg)
```

Switch backend: `VERIFY_ENGINE=rust` + `ANDNA_LIB_PATH=/path/to/libandna_ffi.so`

## Crate Status

| Crate       | Status      | Notes                                                        |
|-------------|-------------|--------------------------------------------------------------|
| contracts   | ✅ Complete | Single source of truth, compile-time assertions              |
| codec       | ✅ Complete | Zero-alloc frame parsing                                     |
| transcript  | ✅ Complete | Real SHAKE256, constant-time comparison                      |
| mldsa44     | ✅ Complete | liboqs backend (default), stub fallback, vendored NIST ACVP KAT |
| core        | ✅ Complete | Orchestrator: parse → pk_hash → μ → verify                   |
| ffi         | ✅ Complete | 8 C ABI functions, 10 error codes, HMAC software integrity (Path A′) |
| Python      | ✅ Complete | ctypes bindings, engine router, frame packer                 |

## Self-Test Sequence

`andna_init()` runs the power-up self-test sequence in a locked order before the
module enters Approved Mode:

```
HMAC-SHA-256 CAST → SHAKE256 KAT → ML-DSA-44 KAT → software integrity check
```

Any failure transitions the module to a sticky Error State; all FFI calls then
return `Internal` until the module is reloaded. See `fips/algorithm_inventory.md`
Section 4 for the full self-test specification.

## Test Inventory

**Rust:**
- contracts: compile-time assertions + runtime checks
- codec: frame pack/unpack, mu_pre parse
- transcript: pk_hash, μ derivation, 3 SHAKE256 KATs
- mldsa44: unit + liboqs roundtrip + vendored NIST ACVP external/pure sigVer harness (10/10)
- core: verify pipeline, frame roundtrip
- ffi: null/length rejection, strerror, version, andna_init self-test gate, HMAC integrity (CAST, reference parsing, full-file verify, tamper rejection)

**Python:**
- test_contracts: locked values, domain separator, error names
- test_frame_packer: SHAKE256 KATs, roundtrip, epoch encoding, validation
- test_engine: Python engine, Rust engine, differential
- test_native: ctypes FFI direct calls
- test_integration: end-to-end HTTP → verify pipeline

> Python tooling is **outside the FIPS cryptographic module boundary** and is
> non-authoritative. Cross-language parity checks are informational only.

## ACVP Vectors

The ML-DSA-44 power-up KAT uses the **vendored official NIST ACVP-Server FIPS 204
sigVer vectors** (external interface, preHash=pure), stored in
`crates/mldsa44/tests/vectors/acvp_mldsa44_sigver.json` with a SHA-256 manifest and
provenance in `crates/mldsa44/tests/vectors/README.md`. The embedded `andna_init()`
KAT uses tcId 11 (expected-valid case); the full harness
(`crates/mldsa44/tests/acvp_sigver.rs`) runs the complete vendored set and passes 10/10.

Tooling: `tests/download_nist_acvp.py` fetches and filters the external/pure vectors;
`tests/extract_kat_for_ffi.py` and `tests/apply_acvp_kat_to_ffi.py` bridge the vendored
vector into the embedded FFI KAT.

This vendored NIST vector is the authoritative power-up KAT. It is distinct from a
CST-lab ACVP test session, which is required for CAVP certificate issuance and has not
yet been performed — see `fips/algorithm_inventory.md` Section 6.

## Audit Logging (Gate 2)

**Authoritative vs. convenience logs.** The AN-DNA CLI produces two output files:

- **`andna_audit.jsonl` (authoritative).** The procurement-grade, tamper-evident
  Gate 2 artifact: strictly monotonic sequence, a single numeric `audit_run_id` per
  session, and a sha3-256 hash chain. Evaluators and auditors must use this file for
  all integrity claims.
- **`verification_log.json` (non-authoritative).** A convenience file for replay UX.
  String-based run IDs, no cryptographic ordering. Not for compliance validation.

**Sequence convention.** The authoritative chain enforces a 0-based index. The genesis
record of each session begins at `seq: 0` with a `prev_hash` of 64 zero bytes.

The Gate 2 `verification_digest` (`85f4dc18...`) anchors deterministic verification
output across hosts; see `fips/gate1_golden.md` Section 8. The `andna-audit` crate
(which produces the chain) uses SHA3-256 and is outside the FIPS cryptographic module
boundary.

## Build Reproducibility (Gate 1)

The release lane produces a cross-host bit-identical two-artifact bundle
(`libandna_ffi.so` + `libandna_ffi.integrity`) under a pinned Docker environment
(Rust 1.93.1, liboqs 0.10.1, LF-normalized sources). The bundle reproduces byte-for-byte
on local Docker and GitHub Actions HostB. See `fips/gate1_golden.md` for current hashes,
the pinned environment, and the cross-host evidence.

## Migration Path

**R1** (current): Core library + Python FFI integration + real ML-DSA-44 + vendored
NIST ACVP KAT + HMAC-SHA-256 software integrity (Path A′) + cross-host reproducible
build. Engineering-complete; the remaining gate is a CST-lab ACVP session for CAVP
certificates.

**R2** (next): Rust verifier service (Axum + Redis) + canary deployment + benchmarks.

## Status and Non-Claims

This repository is pre-validation engineering. It does **not** claim FIPS 140-3
validation or CAVP certification; those require a test session through an accredited
CST laboratory under a CMVP contract. The HMAC-SHA-256 software-integrity key is
non-secret by design and detects unauthorized or accidental modification under the
approved build/deployment process — it is not a defense against a fully privileged
adversary who can rewrite both the module and its reference file. See the `fips/`
package for the complete claims, self-test specifications, and scope limitations.