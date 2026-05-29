# AN-DNA Gate 1 — Cross-Host Build Reproducibility Anchor

**Document:** `/fips/gate1_golden.md`
**Status:** Current
**Version:** 2.1.0
**Date:** 2026-05-28
**Maintainer:** Darrell Morris Jr. — ArcNeura

---

## 1. Purpose

Gate 1 records the SHA-256 of `libandna_ffi.so` as produced by the pinned
reproducibility Dockerfile. The hash serves two complementary functions:

- **Cross-host build reproducibility anchor.** Any conforming host that
  builds the same commit under the pinned environment in Section 3 must
  produce a `libandna_ffi.so` whose SHA-256 matches Section 2. A divergence
  indicates either a non-conforming build environment or post-build tampering.
- **Per-host build integrity anchor.** Within an operational deployment,
  a binary in use whose SHA-256 matches Section 2 is provably the binary
  that was built under the pinned environment against the recorded commit.

Gate 1 is distinct from the `verification_digest` (Gate 2's product-level
determinism anchor). Both anchors are tracked, and they move for different
reasons:

- The `verification_digest` is **toolchain-independent**: it covers
  deterministic verification fields and reproduces identically across any
  conforming implementation on any host. This is what proves cross-host
  product determinism.
- The Gate 1 hash is **build-output-specific**: it changes when source code,
  toolchain version, embedded constants, dependency versions, or the
  compilation environment changes.

The cross-host bit-identical property was empirically verified on
2026-05-28 — see Section 5.

---

## 2. Current Golden Hash

```
sha256(target/release/libandna_ffi.so) =
  4f8af5abb42261133a2ff5359ba61988d82d926b27145175d03a0b94065ad656
```

**Produced by:** `Dockerfile` at repo root, builder stage
(`docker build --target builder`).
**Recorded in image at:** `/build/build-hashes.txt`
**Branch / commit at recording:** `fips/acvp-diagnostics` @ `<fill in: git rev-parse HEAD>`
**Recorded on:** 2026-05-28
**Reproduced on:** Local Windows + Docker Desktop, and GitHub Actions HostB
(Ubuntu) — see Section 5.

This is the cross-host golden hash for the post-ACVP-KAT,
1.93.1-toolchain, LF-normalized binary. Any conforming host that builds
the same commit under the pinned environment must reproduce this value.

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
| Cargo profile | `release` (default — no `codegen-units = 1` required; see Section 9) |
| `Cargo.lock` format | v4 |
| Line endings | LF, enforced repo-wide by `.gitattributes` (`* text=auto eol=lf`) |

See `fips/toolchain_pin.md` for the rationale on the 1.93.1 pin. The line
endings entry is part of the pinned environment because cross-host
bit-identicalness depends on it — see Section 5.

---

## 4. Reproducing the Golden Hash

From any Linux Docker host (including Docker Desktop on Windows or macOS
with a Linux engine):

```bash
cd <repo>
docker build --target builder -t andna-r1:builder .
docker run --rm --entrypoint cat andna-r1:builder /build/build-hashes.txt
```

The printed `sha256` for `target/release/libandna_ffi.so` must match
Section 2. Any divergence indicates a build environment that is not
faithfully pinned to the values in Section 3 — investigate before
recording a new golden.

**On Windows builders specifically:** ensure your local working tree has
LF line endings before building. If `git config core.autocrlf` returns
`true`, the LF policy in `.gitattributes` will only take effect after a
fresh checkout or a `git add --renormalize .` against a clean tree. To
verify, run `git ls-files --eol` and confirm that source files show
`w/lf`, not `w/crlf`. The `COPY . .` step in the Dockerfile copies the
working tree, not git's index, so CRLF in the working tree will produce
divergent input bytes from a Linux checkout.

---

## 5. Cross-Host Reproducibility — Status

**Cross-host bit-identical `libandna_ffi.so` is currently achieved** under
the pinned environment in Section 3.

Verification evidence on 2026-05-28:

| Host | Environment | sha256(libandna_ffi.so) | Status |
|---|---|---|---|
| Local — Windows + Docker Desktop (post-LF-normalization) | Per Section 3 | `4f8af5abb42261133a2ff5359ba61988d82d926b27145175d03a0b94065ad656` | ✓ Matches Golden |
| GitHub Actions HostB — Ubuntu | Per Section 3 | `4f8af5abb42261133a2ff5359ba61988d82d926b27145175d03a0b94065ad656` | ✓ Matches Golden |

### Engineering history of the result

The first attempt at cross-host comparison (2026-05-28, pre-`.gitattributes`)
produced **divergent** hashes:

| Host | Commit | sha256(libandna_ffi.so) |
|---|---|---|
| Local — Windows + Docker Desktop | `01fb35b` | `0515cc640c7d03edb7041f72f25e17ba617dd3469a4863d6f746dad7cc018249` |
| GitHub Actions HostB — Ubuntu | `423b813` | `4f8af5abb42261133a2ff5359ba61988d82d926b27145175d03a0b94065ad656` |

(The two commits differ only in documentation and CI yaml — neither
alters any compiled input, so the divergence was not source-driven.)

The cause was identified via `git ls-files --eol`: the Windows working
tree contained source files with CRLF line endings (`w/crlf` for `.rs`,
`.toml`, `.json`, `.md`, and others), because `core.autocrlf=true` is
the default on Windows. The Dockerfile's `COPY . .` copies the working
tree, not git's index, so local Docker builds compiled CRLF source while
the Linux GitHub Actions checkout compiled LF source. Same commit,
divergent source bytes, divergent binary.

The fix was a `.gitattributes` policy of `* text=auto eol=lf` plus a
`git add --renormalize .` against a clean tree to rewrite the index for
existing files, with binary fixtures (notably `demo/fixtures/*.bin`)
explicitly marked `binary` to prevent EOL conversion from corrupting
them. A subsequent local rebuild from the LF-normalized working tree
produced the matching hash above.

The Gate 2 `verification_digest` remained stable at
`85f4dc18...1159818d` throughout — that anchor is toolchain-independent
and was not affected by either the source-byte divergence or its
resolution.

---

## 6. What This Anchor Covers and Does Not Cover

**Covers:**

- Cross-host bit-identical build reproducibility under the pinned
  environment in Section 3. A matching hash on any conforming host
  proves the binary is byte-identical to the recorded golden.
- Per-host tamper detection. A binary in operational use whose SHA-256
  matches the recorded golden is provably the binary that was built
  under the pinned environment from the recorded commit.

**Does not cover:**

- Product-level verification determinism — that is the
  `verification_digest`, Gate 2's separate anchor. See Section 8 and the
  R1 proof-pack.
- The `andna` CLI binary (`ffi-cli`) — only the FFI shared library is
  hashed.
- Python tooling — outside the FIPS module boundary.
- liboqs internal artifacts.

---

## 7. Non-Claims

- This hash is **not** a CAVP, CMVP, or FIPS 140-3 validation artifact.
- A matching cross-host hash demonstrates build determinism, not algorithm
  correctness or FIPS compliance. Algorithm correctness is established by
  the FIPS self-tests (`fips/algorithm_inventory.md` Section 4) and the
  ACVP external/pure sigVer harness; FIPS compliance requires CST-lab
  engagement.
- The pinned `fips-integrity-stub` is STUB / NON-CONFORMANT and would be
  replaced by HMAC-SHA-256 for any submission-ready artifact — the binary
  hash would change accordingly.
- The cross-host reproducibility property holds for Linux Docker hosts
  building the pinned image. It is not claimed for non-Docker builds,
  for builds with modified Dockerfile environments, or for builds where
  the working-tree line endings have not been normalized to LF.

---

## 8. Companion Anchor — `verification_digest` (Gate 2)

```
verification_digest =
  85f4dc18777bc2122cf671dce6c2d69d92c80b5d0dbd78a83a644afa1159818d
```

This digest covers ONLY deterministic verification fields:
`frame_hash + frame_len + decision + error_code + contract_version`.
It is intentionally toolchain-independent and reproduced across four
independent lanes during the `fips/acvp-diagnostics` sprint: local MSYS2
(rustc 1.92.0), local Docker pre-LF-normalization (rustc 1.93.1), local
Docker post-LF-normalization (rustc 1.93.1), and GitHub Actions HostB
(rustc 1.93.1) — confirming that the ACVP KAT swap, the toolchain bump,
and the line-endings fix did not alter verification semantics, and that
cross-host product determinism holds. See the R1 proof-pack outputs and
`crates/mldsa44/tests/vectors/README.md`.

---

## 9. Additional Optional Hardening — Considered But Not Currently Required

The following Rust-side determinism hardening measures were considered
during the cross-host investigation on 2026-05-28. They were **not
applied** because the line-endings fix alone closed the cross-host gap
without changing compiler behavior or release-build performance. They
remain available if a future scenario requires stricter determinism
guarantees (for example, if the pinned environment must support hosts
with different CPU counts under more demanding determinism constraints):

- `codegen-units = 1` in the release profile. Default is 16; parallel
  codegen ordering can in principle vary across hosts with different
  CPU counts. Cost: substantially slower release builds (codegen no
  longer parallelizes within crates).
- `RUSTFLAGS` path-remap hygiene
  (`--remap-path-prefix=/root/.cargo/registry=/cargo-registry`,
  `--remap-path-prefix=/root/.rustup=/rustup`,
  `--remap-path-prefix=/build=.`) to strip host-specific absolute paths
  potentially embedded in compiled artifacts. The C compiler equivalent
  (`-ffile-prefix-map=...`) is already applied per Section 3.
- `LC_ALL=C` to eliminate any locale-dependent sort/order variance
  during the build.
- `CARGO_INCREMENTAL=0` as explicit documentation (release builds
  default to non-incremental, but the explicit setting prevents
  misconfiguration).

If pursued, these would land as a discrete hardening commit and would
**not** invalidate the current cross-host golden unless they change
compiler-output bytes (which `codegen-units = 1` in particular almost
certainly does). Any such change would trigger a Gate 1 rebaseline and
a corresponding `verification_digest` re-verification.

---

## 10. Revision History

| Version | Date | Hash | Trigger |
|---|---|---|---|
| 1.0.0 | `<prior baseline date>` | `231778903c6c2c345d3eaba423800bc7ec3edb42750518034f083cba40a2ecef` | Initial Gate 1 baseline. Built under Rust 1.76.0, liboqs 0.10.1. Scope and cross-host status not explicitly recorded at the time. |
| 2.0.0 | 2026-05-28 | `0515cc640c7d03edb7041f72f25e17ba617dd3469a4863d6f746dad7cc018249` | Three concurrent intentional changes: (a) ML-DSA-44 init KAT replaced with the official NIST ACVP-Server external/pure sigVer vector (tcId 11) — see `fips/algorithm_inventory.md` v1.3.0 Section 4.2; (b) Pinned toolchain bumped from 1.76.0 → 1.93.1 — see `fips/toolchain_pin.md`; (c) Document temporarily rescoped to per-host build integrity after an initial cross-host comparison showed divergent hashes. Verification_digest (Gate 2) remained stable at `85f4dc18...`. |
| 2.1.0 | 2026-05-28 | `4f8af5abb42261133a2ff5359ba61988d82d926b27145175d03a0b94065ad656` | Cross-host bit-identical reproducibility **achieved** and re-claimed. Root cause of the v2.0.0 divergence was identified as CRLF line endings in the Windows local working tree (Windows `core.autocrlf=true` default), shipped into local Docker builds via `COPY . .` while GitHub Actions Linux checkouts used LF. Fix: `.gitattributes` repo-wide with `* text=auto eol=lf` plus `git add --renormalize .` against a clean tree; binary fixtures explicitly marked `binary` to prevent EOL corruption. Both local Windows Docker Desktop and GitHub Actions HostB now produce identical `sha256(libandna_ffi.so) = 4f8af5ab...` for the same commit. Section 9 (formerly "Future Hardening") repurposed as "Additional Optional Hardening — Considered But Not Currently Required," documenting the deferred Rust-side measures (`codegen-units = 1`, RUSTFLAGS remaps, etc.) and the reasoning for not applying them. Verification_digest (Gate 2) remained stable at `85f4dc18...` throughout. |