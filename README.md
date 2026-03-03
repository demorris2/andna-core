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
  xtask/               # Header regeneration + drift detection
  include/
    andna_vnext_contracts.h  # Generated C constants with _Static_assert guards
    andna_core.h             # C ABI header (cbindgen-generated)
  python/
    andna/                   # Python package
      contracts.py           # Constants mirror (20+ import-time assertions)
      native.py              # ctypes FFI bindings to libandna_ffi.so
      engine.py              # VERIFY_ENGINE feature flag router
      frame_packer.py        # mu_pre builder, frame pack/unpack
    tests/                   # 46 Python tests
  tests/
    generate_transcript_kats.py  # KAT vector generator
    generate_acvp_vectors.py     # ACVP sigVer vector generator (requires liboqs-python)
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

| Crate       | Status           | Notes                                     |
|-------------|------------------|-------------------------------------------|
| contracts   | ✅ Complete      | Single source of truth, 25 compile-time asserts |
| codec       | ✅ Complete      | Zero-alloc frame parsing                  |
| transcript  | ✅ Complete      | Real SHAKE256, constant-time comparison   |
| mldsa44     | ✅ Complete      | liboqs backend (default), stub fallback   |
| core        | ✅ Complete      | Orchestrator: parse → pk_hash → μ → verify |
| ffi         | ✅ Complete      | 5 C ABI functions, 8 error codes          |
| Python      | ✅ Complete      | ctypes bindings, engine router, frame packer |

## Test Inventory

**Rust** (35+ tests):
- contracts: 4 (compile-time assertions + runtime)
- codec: 6 (frame pack/unpack, mu_pre parse)
- transcript: 11 (pk_hash, μ derivation, 3 KATs)
- mldsa44: 4 unit + 5 liboqs roundtrip + 6 ACVP self-gen
- core: 4 (verify pipeline, frame roundtrip)
- ffi: 5 (null/length rejection, strerror, version)

**Python** (46 tests):
- test_contracts: 12 (locked values, domain separator, error names)
- test_frame_packer: 12 (3 KATs, roundtrip, epoch encoding, validation)
- test_engine: 12 (Python engine, Rust engine, differential)
- test_native: 10 (ctypes FFI direct calls)
- test_integration: end-to-end HTTP→verify pipeline

## ACVP Vectors

The `crates/mldsa44/tests/acvp_sigver.rs` harness supports two modes:

1. **Self-generated** (always active with oqs-backend): keygen → sign → verify roundtrip,
   tampered signature rejection, cross-key rejection, pipeline interface test.

2. **Vendored NIST vectors** (optional): place vectors in
   `crates/mldsa44/tests/vectors/acvp_mldsa44_sigver.json`.
   Generate with `python tests/generate_acvp_vectors.py` (requires liboqs-python).

## Migration Path

**R1** (current): Core library + Python FFI integration + real ML-DSA-44 + ACVP gate
**R2** (next): Rust verifier service (Axum + Redis) + canary deployment + benchmarks
