# CLAUDE.md — andna-core house rules

Context for any agentic session in this repository. Read fully before editing anything.

## Project in one paragraph

AN-DNA is a post-quantum device/object trust system: D0 (epoch-ratcheted identity
derivation, fips204/ML-DSA-44) → R1 (liboqs ML-DSA-44 frame verifier with deterministic
evidence) → R2 (pure, oqs-free local policy/authorization engine) → andna-pipeline (the one
seam composing R1+R2) → andna-seal (file sealing via mu_pre.ctx_hash binding) → ffi_cli
("andna" operator CLI). Falsifiable, bounded claims only. Procurement-grade discipline.

## Hard invariants — never violate

1. **R1 is frozen.** Never modify the verifier (`crates/core` verify path), `crates/ffi`
   crypto/integrity code, or anything Golden-Hash/Gate-1 anchored. If a test fails against
   R1, fix the caller, never the verifier.
2. **No second verifier.** All verification goes through `andna_core::verify_frame_v2` /
   `andna_pipeline::verify_and_authorize`. Never reimplement frame parsing+signature
   checking elsewhere. (Reading public fields at contract offsets is fine; deciding
   validity is not.)
3. **R2 stays oqs-free.** `cargo tree -p andna-r2` must never show oqs/oqs-sys/liboqs.
   Same for `andna-d0`. CI enforces this; don't add deps that break it.
4. **Constants live in `andna-contracts`.** Never duplicate offsets/lengths; import them.
   The ffi/xtask HMAC-constant duplication is intentional (frozen-boundary decision) — do
   not consolidate it.
5. **No secrets in git.** `.andna/` is gitignored (sealer/verifier profiles contain seed
   material). Never commit profiles, never print seeds into docs. Fixed TEST seeds used via
   `--seed-hex` in demos are allowed only when clearly labeled "TEST SEED — demo only".
6. **Claim boundaries are law.** `docs/file-seal/file-seal-claim-boundaries.md` governs all
   public-facing language. Reference it; never fork or paraphrase-expand its claims. Never
   write: hardware custody, clone resistance, FIPS-validated, encryption, "impossible to
   forge", or "replaces Sigstore/SLSA/TUF/in-toto".
7. **Review freeze (active).** Until the independent cryptographic review returns: no D0
   production-claim code, no R2 claim expansion, no new cryptographic mechanisms, no
   architecture-packet rewrites. Docs, demos, tests, and hygiene only.

## Build & test (environment facts)

- Windows dev box: cargo runs in MSYS2 MinGW64; git in Git Bash. Linux CI: ubuntu-latest.
- `cargo test --workspace` FAILS by design: `andna-ffi` has a compile_error! feature gate.
  Correct full-test invocation:
  - `cargo test --workspace --exclude andna-ffi --exclude ffi-cli --locked`
  - FFI separately: `cargo test -p andna-ffi --locked --features "oqs-backend fips-integrity-hmac fips-kat-vectors-embedded" -- --test-threads=1`
- CLI build: `cargo build -p ffi-cli --locked --features "oqs-backend fips-integrity-stub"`
- Operator contract: `bash scripts/file_seal_cli_contract.sh` → must end `PASS: file-seal CLI contract`
- Seal/evidence: `cargo test -p andna-seal --locked` (15 tests). Pipeline:
  `cargo test -p andna-pipeline --locked` (4 tests).
- Windows quirk: Application-Control AV may block fresh test exes (os error 4551) — rerun.
- `cargo fmt --all` before every commit; CI checks it.

## Style rules (earned the hard way)

- **No backslash line continuations in any shell script** — pasted continuations have been
  destroyed twice on the dev box. One command per line. The contract script declares this
  rule in a header comment; preserve it.
- Multi-line `git commit -m` messages are banned in interactive shells; use multiple
  single-line `-m` flags (Claude Code may use commit-message files safely).
- Every delivered file is identified by FULL destination path. Every crate has a
  `src/lib.rs`; the directory, not the filename, is the identity.
- Tests assert exact error variants / exact output strings (the CLI's kv column spacing in
  grep assertions is intentional — do not "clean it up").
- Diagnostic tests are removed before final commit; the suite stays procurement-clean.

## Branch & merge discipline

scoped branch → local validation → push → CI green (file-seal-lane, governance, and any
touched lane) → PR → merge. Never merge red. Never work directly on main.

## Where things live

- Contracts/offsets: `crates/contracts`. Verifier: `crates/core`. Policy: `crates/andna-r2`.
- Composition: `crates/pipeline`. Sealing+evidence: `crates/andna-seal`.
- CLI: `ffi_cli` (binary name `andna`). Operator contract: `scripts/file_seal_cli_contract.sh`.
- Docs: `docs/file-seal/`. CI: `.github/workflows/{file-seal.yml,governance.yml,...}`.