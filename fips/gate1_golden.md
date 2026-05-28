# AN-DNA Gate 1 — Reproducible Build Golden Hash

**Document:** `/fips/gate1_golden.md`
**Status:** Current
**Version:** 2.0.0
**Date:** 2026-05-28
**Maintainer:** Darrell Morris Jr. — ArcNeura

---

## 1. Purpose

Gate 1 of the AN-DNA reproducibility ladder asserts that the pinned Docker build
produces a **bit-identical `libandna_ffi.so` across hosts**. This document records
the current Golden Hash — the SHA-256 of that binary as built in the pinned
reproducibility lane — and the exact environment that produced it.

Gate 1 is distinct from the `verification_digest` (Gate 2's product-level
determinism anchor). Both must be tracked, and they move for different reasons.
The `verification_digest` changes only when verification semantics change. The
Gate 1 hash changes whenever any input to the binary build changes: source code,
toolchain version, embedded constants, dependency versions.

---

## 2. Current Golden Hash

```
sha256(target/release/libandna_ffi.so) =
  0515cc640c7d03edb7041f72f25e17ba617dd3469a4863d6f746dad7cc018249
```

**Produced by:** `Dockerfile` at repo root, builder stage (`docker build --target builder`)
**Recorded in image at:** `/build/build-hashes.txt`
**Branch / commit at recording:** `fips/acvp-diagnostics` @ `<fill in: git rev-parse HEAD>`
**Recorded on:** 2026-05-28

---

## 3. Pinned Build Environment

| Component | Pinned value |
|---|---|
| Base image | `debian@sha256:74d56e3931e0d5a1dd51f8c8a2466d21de84a271cd3b5a733b803aa91abf4421` |
| Rust toolchain | `1.93.1` (via `ARG RUST_VERSION` and `ENV RUSTUP_TOOLCHAIN`) |
| liboqs | `0.10.1` (built from source, `OQS_BUILD_ONLY_LIB=ON`, `OQS_DIST_BUILD=ON`) |
| `SOURCE_DATE_EPOCH` | `1772150400` |
| `CFLAGS` / `CXXFLAGS` | `-ffile-prefix-map=/tmp/liboqs=. -ffile-prefix-map=/build=.` |
| FIPS feature set | `oqs-backend fips-integrity-stub fips-kat-vectors-embedded` |
| Cargo profile | `release` |
| `Cargo.lock` format | v4 |

See `fips/toolchain_pin.md` for the rationale on the 1.93.1 pin.

---

## 4. Reproducing the Hash

From any Linux host with Docker (network access required for the first build):

```bash
cd <repo>
docker build --target builder -t andna-r1:builder .
docker run --rm --entrypoint cat andna-r1:builder /build/build-hashes.txt
```

The printed `sha256  target/release/libandna_ffi.so` line must match the
Golden Hash in Section 2. Any divergence indicates the build environment is
not faithfully pinned to the values in Section 3 — investigate before
recording a new golden.

---

## 5. Cross-Host Reproduction Status

| Host | Environment | sha256(libandna_ffi.so) | Status | Date |
|---|---|---|---|---|
| Local — Windows + Docker Desktop | Per Section 3 | `0515cc640c7d03edb7041f72f25e17ba617dd3469a4863d6f746dad7cc018249` | ✓ Matches Golden | 2026-05-28 |
| GitHub Actions HostB | Per Section 3 | `<fill in once CI builds with the bumped Dockerfile>` | Pending CI run | TBD |

The cross-host reproduction proof requires a second independent build of the
same commit under the same pinned environment. The CI HostB lane provides the
second host. When the HostB workflow runs the post-toolchain-bump build,
capture its `build-hashes.txt` value above; it must equal the local hash. If
it does not, Section 3 is incomplete — some input is varying across hosts.

---

## 6. What This Hash Covers and Does Not Cover

**Covers:** the exact bytes of the `libandna_ffi.so` shared library produced
by the pinned reproducibility lane. Two hosts producing the same hash
demonstrates that the build is deterministic with respect to the pinned
environment.

**Does not cover:**

- Product-level verification determinism — that is the `verification_digest`,
  Gate 2's separate anchor. See Section 8 and the R1 proof-pack.
- The `andna` CLI binary (`ffi-cli`) — only the FFI shared library is hashed.
- Python tooling — outside the FIPS module boundary.
- liboqs internal artifacts.

---

## 7. Non-Claims

- This hash is **not** a CAVP, CMVP, or FIPS 140-3 validation artifact.
- A matching hash across hosts demonstrates build determinism, not algorithm
  correctness or FIPS compliance. Algorithm correctness is established by
  the FIPS self-tests (`fips/algorithm_inventory.md` Section 4) and the
  ACVP external/pure sigVer harness; FIPS compliance requires CST-lab
  engagement.
- The pinned `fips-integrity-stub` is STUB / NON-CONFORMANT and would be
  replaced by HMAC-SHA-256 for any submission-ready artifact — the binary
  hash would change accordingly.

---

## 8. Companion Anchor — `verification_digest` (Gate 2)

```
verification_digest =
  85f4dc18777bc2122cf671dce6c2d69d92c80b5d0dbd78a83a644afa1159818d
```

This digest covers ONLY deterministic verification fields:
`frame_hash + frame_len + decision + error_code + contract_version`.
It is intentionally toolchain-independent and reproduced across local
(rustc 1.92.0) and pinned Docker (rustc 1.93.1) lanes during the
`fips/acvp-diagnostics` sprint, confirming that the ACVP KAT swap and the
toolchain bump did not alter verification semantics. See the R1 proof-pack
outputs and `crates/mldsa44/tests/vectors/README.md`.

---

## 9. Revision History

| Version | Date | Hash | Trigger |
|---|---|---|---|
| 1.0.0 | `<prior baseline date>` | `231778903c6c2c345d3eaba423800bc7ec3edb42750518034f083cba40a2ecef` | Initial Gate 1 baseline. Built under Rust 1.76.0, liboqs 0.10.1. |
| 2.0.0 | 2026-05-28 | `0515cc640c7d03edb7041f72f25e17ba617dd3469a4863d6f746dad7cc018249` | Two concurrent intentional changes: (a) ML-DSA-44 init KAT replaced with the official NIST ACVP-Server external/pure sigVer vector (tcId 11) — see `fips/algorithm_inventory.md` v1.3.0 Section 4.2; (b) Pinned toolchain bumped from 1.76.0 → 1.93.1 to consolidate Docker, CI, and local dev on a single toolchain and resolve recurring lock-format and rlib incompatibilities — see `fips/toolchain_pin.md`. Both changes intentionally rebased the binary. The `verification_digest` (Gate 2) remained stable at `85f4dc18...`, confirming that verification semantics were untouched by either change. |