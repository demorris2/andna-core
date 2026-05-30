# AN-DNA Reproducibility Lane — Toolchain Pin

**Document:** `/fips/toolchain_pin.md`
**Status:** Current
**Version:** 1.1.0
**Date:** 2026-05-28
**Maintainer:** Darrell Morris Jr. — ArcNeura

---

## 1. Pinned Toolchain

The AN-DNA reproducibility lane is pinned to **Rust 1.93.1**.

The pin is enforced redundantly across three locations so that no single
configuration file or environment variable can silently override it:

| Location | Mechanism | Value |
|---|---|---|
| `Dockerfile` | `ARG RUST_VERSION` (used by the rustup install in the builder stage) | `1.93.1` |
| `Dockerfile` | `ENV RUSTUP_TOOLCHAIN=${RUST_VERSION}` (overrides any in-repo `rust-toolchain` file) | `1.93.1` |
| `rust-toolchain.toml` | rustup channel selector for local development | `1.93.1` |

The redundancy is deliberate. `RUSTUP_TOOLCHAIN` sits higher in rustup's
override precedence than `rust-toolchain.toml`, so if a future contributor
introduces a conflicting toolchain file, the Docker lane still builds with
the pinned version. The `rust-toolchain.toml` keeps local rustup-managed
shells aligned with the same pin.

---

## 2. Why 1.93.1

Prior to 2026-05-28 the Docker lane was pinned to **Rust 1.76.0** — the
version in use when the original Gate 1 baseline was recorded
(`gate1_golden.md` revision 1.0.0). Local development had since moved to
1.92.0 (MSYS2 system rust) and 1.93.1 (rustup, honoring the existing
`rust-toolchain.toml`). This split produced a recurring class of breakages
whose common root cause was *more than one cargo version touching a single
repo*:

1. **`Cargo.lock` v4 incompatibility.** Local cargo 1.92/1.93 rewrote
   `Cargo.lock` to format version 4 (stabilized in Rust 1.78). Cargo 1.76.0
   could not parse v4, breaking the Docker build whenever the lock was
   updated locally.
2. **Silent toolchain override.** The repo's `rust-toolchain.toml` (channel
   `1.93.1`) was copied into the Docker build by `COPY . .` and overrode
   the Dockerfile's intended 1.76.0, causing cargo to attempt a mid-build
   toolchain download.
3. **`target/` rlib incompatibility.** Sharing `target/` between MSYS2
   (1.92.0) and PowerShell (1.93.1) shells produced E0514 rlib-format
   errors and required `cargo clean` on every shell switch.

Patching each symptom individually generated new ones, so on 2026-05-28 the
decision was made to consolidate every lane onto a single toolchain. The
choice between **consolidating down to 1.76.0** and **bumping up to 1.93.1**
was made on the following grounds:

- The Gate 1 hash was already being rebaselined because of an unrelated
  change (the ACVP-derived ML-DSA-44 KAT replacement), so the cost of a
  toolchain rebaseline was zero on top of work already required.
- The repo's existing `rust-toolchain.toml` already specified 1.93.1, so
  bumping Docker aligned the pin *with where the repo already pointed*
  rather than dragging local dev backward.
- 1.93.1 reads `Cargo.lock` v4 natively, eliminating the lock-format
  problem permanently.
- Downgrading dependencies to a 1.76.0-compatible lock posed a non-zero
  risk of MSRV (minimum supported Rust version) failures in transitive
  dependencies.

For the reproducibility claim, what matters is that the toolchain is
**pinned and identical across hosts**, not that it is any particular
version. 1.93.1 pinned is no less defensible than 1.76.0 pinned and is
materially less likely to break.

---

## 3. Scope of the Pin

The pin governs the AN-DNA reproducibility lane: the build environment that
produces the artifact tracked by `fips/gate1_golden.md`. It does not
constrain arbitrary local development outside that lane (for example,
experimenting with newer compilers in branches that are not built for
reproducibility evidence).

Contributors who want their local builds to track the pin should ensure
their shell uses the rustup-managed toolchain that honors
`rust-toolchain.toml`, rather than a parallel system rust such as MSYS2's
pacman package, which ignores it. Two consistent practices keep local and
Docker hashes reproducible:

1. **Use one rustup installation across all shells.** Put `~/.cargo/bin`
   ahead on PATH in every terminal so all shells resolve to the same cargo,
   which then honors `rust-toolchain.toml` → 1.93.1.
2. **Or isolate `target/` per terminal** with a distinct `CARGO_TARGET_DIR`,
   so different compilers never share build artifacts.

Failing to do either is not a correctness problem (the pinned Docker build
remains authoritative), but it produces local frictions like E0514 rlib
mismatches that resolve only by `cargo clean`.

---

## 4. Relationship to Other Anchors

This pin determines the **binary-bytes** anchor (Gate 1 / `gate1_golden.md`).
It does not affect the **product-level verification** anchor (Gate 2 /
`verification_digest`), which is by design toolchain-independent. The ACVP
sprint demonstrated this: the `verification_digest` reproduced unchanged
across builds under three different toolchains (1.76.0, 1.92.0, 1.93.1)
during the transition.

---

## 5. Related Reproducibility Hygiene — Line Endings

The toolchain pin alone is not sufficient for cross-host bit-identical
Rust builds. A separate input that must be normalized is **source file
line endings**. Windows installs of Git default to `core.autocrlf=true`,
which materializes source files with CRLF line endings in the working
tree even when the index stores LF. The Dockerfile's `COPY . .` copies
the working tree, not the index, so a Windows local Docker build will
compile CRLF source while a Linux GitHub Actions checkout compiles LF
source — for the same commit. The empirical investigation on 2026-05-28
identified this as the cause of an initial cross-host hash divergence;
see `fips/gate1_golden.md` Section 5 for the full diagnostic and
resolution.

The fix lives in `.gitattributes` (repo-wide `* text=auto eol=lf`, plus
explicit `binary` markers for `.bin`/`.png`/`.so`/etc. fixtures so they
are never EOL-converted). This is documented separately from the
toolchain pin because its scope and mechanism are independent of the
Rust toolchain itself, but the two together form the complete pinned
environment required for cross-host bit-identical Rust output.

---

## 6. Non-Claims

- This pin is a build-reproducibility configuration, not a security
  attestation. It does not constitute or substitute for FIPS 140-3
  validation, a CAVP certificate, or an ACVP test session.
- Rust 1.93.1 is not endorsed by NIST or any CMVP body for any
  cryptographic purpose. Any cryptographic claims of the AN-DNA module
  rest on the algorithms, self-tests, and lab engagement described in
  `fips/algorithm_inventory.md`, not on the Rust toolchain version.

---

## 7. Revision History

| Version | Date | Change |
|---|---|---|
| 1.0.0 | 2026-05-28 | Initial pin documentation. Pin set to Rust 1.93.1, consolidating the Docker reproducibility lane with the existing `rust-toolchain.toml` and local development. Supersedes the prior 1.76.0 Docker pin. Concurrent with `gate1_golden.md` revision 2.0.0. |
| 1.1.0 | 2026-05-28 | Added Section 5 documenting the related line-endings hygiene (`.gitattributes` with `eol=lf`), identified during the cross-host investigation on 2026-05-28 as a co-requirement for cross-host bit-identical Rust builds. The toolchain pin and the line-endings policy together form the complete pinned environment; see `fips/gate1_golden.md` Section 5 for the full diagnostic. |