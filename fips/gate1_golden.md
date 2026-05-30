# AN-DNA Gate 1 — Cross-Host Build Reproducibility Anchor

**Document:** `/fips/gate1_golden.md`
**Status:** Current
**Version:** 2.2.0
**Date:** 2026-05-30
**Maintainer:** Darrell Morris Jr. — ArcNeura

---

## 1. Purpose

Gate 1 records the SHA-256 hashes of the **two-artifact integrity bundle**
produced by the pinned reproducibility Dockerfile:

1. `libandna_ffi.so` — the cryptographic module shared library
2. `libandna_ffi.integrity` — the associated `ANDNA-INTEGRITY-v1`
   reference file consumed by the module's HMAC software-integrity
   self-test (see `fips/algorithm_inventory.md` Section 4.4)

Both artifacts ship together as a bundle. The bundle serves two
complementary functions:

- **Cross-host build reproducibility anchor.** Any conforming host that
  builds the same commit under the pinned environment in Section 3 must
  produce a bundle whose two SHA-256 hashes match Section 2. A divergence
  indicates either a non-conforming build environment or post-build tampering.
- **Per-host build integrity anchor.** Within an operational deployment,
  a bundle in use whose hashes match Section 2 is provably the bundle
  that was built under the pinned environment against the recorded commit.

Gate 1 is distinct from the `verification_digest` (Gate 2's product-level
determinism anchor). Both anchors are tracked, and they move for different
reasons:

- The `verification_digest` is **toolchain-independent**: it covers
  deterministic verification fields and reproduces identically across any
  conforming implementation on any host. This is what proves cross-host
  product determinism.
- The Gate 1 bundle hashes are **build-output-specific**: they change when
  source code, toolchain version, embedded constants, dependency versions,
  the compilation environment, or the integrity key changes.

Cross-host bit-identical reproducibility for the bundle was empirically
verified on 2026-05-30 — see Section 5.

---

## 2. Current Golden Bundle

```
sha256(target/release/libandna_ffi.so) =
  47980d69be7061612557201105db77f1aa239781f89f4c1526992b3672a7e8fb

sha256(target/release/libandna_ffi.integrity) =
  6ce7360e745278a6622fe3e12483e9e8a2be6478a0997bed7466313092905304
```

**Produced by:** `Dockerfile` at repo root, builder stage
(`docker build --target builder`), followed by `xtask write-integrity-reference`.
**Recorded in image at:** `/build/build-hashes.txt`
**Branch / commit at recording:** `fips/hmac-integrity` @ `<fill in: git rev-parse HEAD>`
**Recorded on:** 2026-05-30
**Reproduced on:** Local Windows + Docker Desktop, and GitHub Actions HostB
(Ubuntu) — see Section 5.

This is the cross-host golden bundle for the post-HMAC-integrity,
1.93.1-toolchain, LF-normalized build. Any conforming host that builds
the same commit under the pinned environment must reproduce both values.

> **Relationship between the two hashes:** The `.integrity` file
> embeds both the SHA-256 of the `.so` and an HMAC-SHA-256 over the
> same bytes (using the embedded non-secret integrity key). The two
> hashes are therefore not independently varying — if the `.so` hash
> reproduces, the `.integrity` hash will too, given the deterministic
> generator. Both are recorded so that a reviewer can verify either or
> both independently.

---

## 3. Pinned Build Environment

| Component | Pinned value |
|---|---|
| Base image | `debian@sha256:74d56e3931e0d5a1dd51f8c8a2466d21de84a271cd3b5a733b803aa91abf4421` |
| Rust toolchain | `1.93.1` (via `ARG RUST_VERSION` and `ENV RUSTUP_TOOLCHAIN`) |
| liboqs | `0.10.1` (built from source, `OQS_BUILD_ONLY_LIB=ON`, `OQS_DIST_BUILD=ON`) |
| `SOURCE_DATE_EPOCH` | `1772150400` |
| `CFLAGS` / `CXXFLAGS` | `-ffile-prefix-map=/tmp/liboqs=. -ffile-prefix-map=/build=.` |
| FIPS feature set | `oqs-backend fips-integrity-hmac fips-kat-vectors-embedded` |
| Integrity reference generator | `cargo run -p xtask -- write-integrity-reference <module> <ref>` |
| Cargo profile | `release` (default — no `codegen-units = 1` required; see Section 9) |
| `Cargo.lock` format | v4 |
| Line endings | LF, enforced repo-wide by `.gitattributes` (`* text=auto eol=lf`) |

See `fips/toolchain_pin.md` for the rationale on the 1.93.1 pin. The line
endings entry is part of the pinned environment because cross-host
bit-identicalness depends on it — see Section 5.

The integrity reference generator is part of the pinned environment because
the `.integrity` file is part of the bundle. The generator is deterministic:
given the same `.so` and the same integrity key, it produces the same
`.integrity` file bytes.

---

## 4. Reproducing the Golden Bundle

From any Linux Docker host (including Docker Desktop on Windows or macOS
with a Linux engine):

```bash
cd <repo>
docker build --target builder -t andna-r1:builder .
docker run --rm --entrypoint cat andna-r1:builder /build/build-hashes.txt
```

The printed `sha256` lines for both `target/release/libandna_ffi.so` and
`target/release/libandna_ffi.integrity` must match Section 2. Any
divergence indicates a build environment that is not faithfully pinned
to the values in Section 3 — investigate before recording a new golden.

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

**Cross-host bit-identical bundle reproduction is currently achieved**
under the pinned environment in Section 3.

Verification evidence on 2026-05-30:

| Host | Environment | sha256(libandna_ffi.so) | sha256(libandna_ffi.integrity) | Status |
|---|---|---|---|---|
| Local — Windows + Docker Desktop | Per Section 3 | `47980d69be7061612557201105db77f1aa239781f89f4c1526992b3672a7e8fb` | `6ce7360e745278a6622fe3e12483e9e8a2be6478a0997bed7466313092905304` | ✓ Matches Golden |
| GitHub Actions HostB — Ubuntu | Per Section 3 | `47980d69be7061612557201105db77f1aa239781f89f4c1526992b3672a7e8fb` | `6ce7360e745278a6622fe3e12483e9e8a2be6478a0997bed7466313092905304` | ✓ Matches Golden |

### Engineering history of the result

The cross-host parity result above represents the cumulative state of three
sequential reproducibility investigations:

**1. Initial cross-host divergence (2026-05-28, pre-`.gitattributes`).**
Same-commit local Windows Docker and GitHub Actions HostB produced
divergent `libandna_ffi.so` hashes (`0515cc64...` vs `4f8af5ab...`).
Root cause was identified via `git ls-files --eol`: Windows `core.autocrlf=true`
shipped CRLF source into local Docker via `COPY . .` while the Linux GitHub
Actions checkout used LF. Same commit, divergent source bytes, divergent
binary.

**Fix:** `.gitattributes` policy of `* text=auto eol=lf` plus a
`git add --renormalize .` against a clean tree to rewrite the index for
existing files, with binary fixtures (notably `demo/fixtures/*.bin`)
explicitly marked `binary` to prevent EOL conversion from corrupting them.
A subsequent local rebuild from the LF-normalized working tree produced
`4f8af5ab...` on both hosts. This was recorded as v2.1.0 of this document.

**2. Toolchain consolidation (2026-05-28).** Local development and Docker
were split across Rust 1.76.0 (Docker) and 1.93.1 (local rustup honoring
`rust-toolchain.toml`). Cargo lock format v4 incompatibility broke the
Docker lane. Pin consolidated to 1.93.1 across all lanes; see
`fips/toolchain_pin.md`.

**3. HMAC software integrity sprint (2026-05-30).** The `fips-integrity-hmac`
feature replaced the prior `fips-integrity-stub` placeholder, adding a
real full-file HMAC-SHA-256 software integrity check (Path A′; see
`fips/algorithm_inventory.md` Section 4.4). This changed the module
binary's content (new feature, new code, new self-test) and introduced
the second bundle artifact (`libandna_ffi.integrity`). The new bundle
hashes — `47980d69...` and `6ce7360e...` — are recorded above.

The Gate 2 `verification_digest` remained stable at
`85f4dc18...1159818d` throughout all three investigations — that anchor
is toolchain-independent and was not affected by any of the source-byte
divergences, the toolchain bump, or the addition of the HMAC integrity
mechanism.

---

## 6. What This Anchor Covers and Does Not Cover

**Covers:**

- Cross-host bit-identical build reproducibility for the two-artifact
  bundle under the pinned environment in Section 3. Matching bundle
  hashes on any conforming host prove the artifacts are byte-identical
  to the recorded golden.
- Per-host tamper detection. A bundle in operational use whose hashes
  match the recorded golden is provably the bundle that was built under
  the pinned environment from the recorded commit.

**Does not cover:**

- Product-level verification determinism — that is the
  `verification_digest`, Gate 2's separate anchor. See Section 8 and the
  R1 proof-pack.
- The `andna` CLI binary (`ffi-cli`) — only the FFI shared library and
  its integrity reference are hashed.
- Python tooling — outside the FIPS module boundary.
- liboqs internal artifacts.
- Tamper resistance against a fully privileged adversary capable of
  rewriting both the module and its reference file. See
  `fips/algorithm_inventory.md` Section 7 (Non-Claims) for the bounded
  security claim of the HMAC integrity mechanism.

---

## 7. Non-Claims

- This bundle is **not** a CAVP, CMVP, or FIPS 140-3 validation artifact.
- A matching cross-host bundle demonstrates build determinism, not
  algorithm correctness or FIPS compliance. Algorithm correctness is
  established by the FIPS self-tests (`fips/algorithm_inventory.md`
  Section 4) and the ACVP external/pure sigVer harness; FIPS compliance
  requires CST-lab engagement.
- The HMAC-SHA-256 integrity mechanism described here is not claimed to
  defend against a privileged adversary who can rewrite both the module
  and its reference file. The integrity key is non-secret and embedded
  in the module by design; see `fips/algorithm_inventory.md` Section 7.
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
It is intentionally toolchain-independent and reproduced across
independent lanes during the `fips/acvp-diagnostics` and
`fips/hmac-integrity` sprints: local MSYS2 (rustc 1.92.0), local Docker
pre-LF-normalization (rustc 1.93.1), local Docker post-LF-normalization
(rustc 1.93.1), GitHub Actions HostB (rustc 1.93.1) pre-HMAC, and
GitHub Actions HostB (rustc 1.93.1) post-HMAC. Confirming that the ACVP
KAT swap, the toolchain bump, the line-endings fix, and the HMAC
software integrity addition did not alter verification semantics, and
that cross-host product determinism holds.

See the R1 proof-pack outputs and `crates/mldsa44/tests/vectors/README.md`.

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

| Version | Date | Bundle | Trigger |
|---|---|---|---|
| 1.0.0 | `<prior baseline date>` | `libandna_ffi.so` = `231778903c6c2c345d3eaba423800bc7ec3edb42750518034f083cba40a2ecef` (single-artifact anchor; no `.integrity` companion existed) | Initial Gate 1 baseline. Built under Rust 1.76.0, liboqs 0.10.1, with `fips-integrity-stub` (placeholder). Scope and cross-host status not explicitly recorded at the time. |
| 2.0.0 | 2026-05-28 | `libandna_ffi.so` = `0515cc640c7d03edb7041f72f25e17ba617dd3469a4863d6f746dad7cc018249` (single-artifact; cross-host divergent during recording) | Three concurrent intentional changes: (a) ML-DSA-44 init KAT replaced with the official NIST ACVP-Server external/pure sigVer vector (tcId 11); (b) Pinned toolchain bumped from 1.76.0 → 1.93.1; (c) Document temporarily rescoped to per-host build integrity after an initial cross-host comparison showed divergent hashes. `verification_digest` (Gate 2) remained stable at `85f4dc18...`. |
| 2.1.0 | 2026-05-28 | `libandna_ffi.so` = `4f8af5abb42261133a2ff5359ba61988d82d926b27145175d03a0b94065ad656` (single-artifact; cross-host bit-identical) | Cross-host bit-identical reproducibility **achieved** and re-claimed. Root cause of the v2.0.0 divergence was identified as CRLF line endings in the Windows local working tree; fix via `.gitattributes` repo-wide `* text=auto eol=lf` plus `git add --renormalize .`. Both local Windows Docker Desktop and GitHub Actions HostB now produced identical `sha256(libandna_ffi.so) = 4f8af5ab...`. `verification_digest` (Gate 2) remained stable at `85f4dc18...`. |
| 2.2.0 | 2026-05-30 | `libandna_ffi.so` = `47980d69be7061612557201105db77f1aa239781f89f4c1526992b3672a7e8fb`; `libandna_ffi.integrity` = `6ce7360e745278a6622fe3e12483e9e8a2be6478a0997bed7466313092905304` (two-artifact bundle; cross-host bit-identical) | **Structural shift: Gate 1 anchor becomes a two-artifact bundle.** The `fips-integrity-hmac` feature replaces the prior `fips-integrity-stub` placeholder, adding a real full-file HMAC-SHA-256 software-integrity check (Path A′) and introducing the `libandna_ffi.integrity` reference file as the second bundle artifact. The module binary changes content (new feature, new code, new self-test); the bundle now contains both the `.so` and the generator-produced `.integrity` file. Both artifacts reproduce bit-identically across local Windows Docker Desktop and GitHub Actions HostB. Sections 1, 2, 3, 4, 5, 6 restructured to reflect the bundle anchor; Section 8 updated to reflect HMAC-sprint validation of `verification_digest` stability. Section 9 unchanged. `verification_digest` (Gate 2) confirmed stable at `85f4dc18...` post-HMAC-integrity. |