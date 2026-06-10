# AN-DNA File-Seal CI Lane

Workflow file: `.github/workflows/file-seal.yml`  
Workflow name: `file-seal-lane`  
Primary purpose: keep the file-seal milestone green on Linux for relevant pushes and pull requests.

## What the lane protects

The file-seal lane protects the working path from file/object sealing through R1 verification, R2 authorization, evidence output, and operator-level CLI behavior. Also the lane also pins the toolchain via rust-toolchain.toml and caches the liboqs
build (first cold run ~minutes, cached runs fast).

The lane currently runs:

1. Rust formatting check
2. R2 backend isolation check
3. `andna-seal` library tests
4. `andna-pipeline` end-to-end tests
5. file-seal CLI contract script

## Trigger scope

The lane runs for changes touching:

- `crates/andna-seal/**`
- `crates/andna-r2/**`
- `crates/pipeline/**`
- `ffi_cli/**`
- `scripts/file_seal_cli_contract.sh`
- `Cargo.lock`
- `.github/workflows/file-seal.yml`

It runs on:

- pushes to `main`
- pushes to `feature/**`
- pushes to `recovery/**`
- pull requests into `main`
- manual workflow dispatch

## Why the CLI contract is shell-based

The operator contract is intentionally implemented as a shell script instead of a Rust integration test.

Reasons:

- local Windows Application Control can block generated Rust test executables under `target/debug/deps`
- nested `cargo run` from inside `cargo test` can create target-directory lock contention
- the product surface is the actual CLI binary, so the script validates the operator-visible behavior directly

The script builds `ffi-cli`, resolves the correct platform binary, runs the four-command surface, checks evidence output, and validates expected failure modes.

## Backend isolation check

The lane verifies that `andna-r2` remains free of OQS/liboqs dependencies.

Rationale:

- R2 should remain a policy/authorization layer
- R1 owns the cryptographic verification boundary
- keeping R2 OQS-free reduces build burden and preserves architectural separation

## Expected green-lane statement

A green run supports this statement:

> The file-seal lane passes formatting, R2 backend isolation, seal/evidence library tests, R1→R2 pipeline tests, and the operator-level CLI contract including evidence v1 and attestation cases.

## What the lane does not prove

The lane does not prove:

- FIPS validation
- ACVP readiness
- hardware-backed custody
- production key management
- enterprise IAM readiness
- malware safety of sealed files
- complete workspace governance health if unrelated governance checks are intentionally deferred

## Recommended branch rule

Before merging file-seal changes into `main`, require the `file-seal-lane` workflow to pass.

Recommended local pre-push check:

```bash
cargo fmt --all
cargo test -p andna-seal --locked
cargo test -p andna-pipeline --locked
bash scripts/file_seal_cli_contract.sh
```
