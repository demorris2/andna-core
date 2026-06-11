# AN-DNA File-Seal Evidence Demo

This directory contains a local GUI demo for the AN-DNA file-seal evidence workflow.

## Architecture rule

This demo is a thin shell over the `andna` CLI binary. It invokes the CLI via `subprocess`, reads CLI exit codes and the emitted evidence JSON, and renders those results. It must contain zero verification logic, zero frame parsing for validity decisions, and zero cryptography. The `andna` CLI remains the sole authoritative engine. The file-seal CLI contract script remains the source of truth for behavior.

## What the demo shows

The UI exposes four actions:

- `Seal File` runs `andna seal-file` on a local sample file, writes the sidecar and registry into a temporary directory, then displays the CLI seal/inspect summary.
- `Tamper File` appends bytes to the working copy of the sample file and marks it as tampered.
- `Verify File` runs `andna verify-file --evidence-out`, renders a large `ACCEPT` or `REJECT`, and shows `AUTHENTIC`, `UNCHANGED`, and `AUTHORIZED` using values from the evidence JSON.
- `Show Evidence` renders the evidence JSON, visually separating the deterministic section, runtime section, and `evidence_digest_hex`.

Evidence caption shown by the UI:

```text
 digest covers the deterministic section only; runtime fields are recorded but digest-exempt.
```

Footer claim line shown by the UI:

```text
AN-DNA File-Seal demo — software-profile identity; integrity/authenticity binding only; this does not encrypt files. See docs/file-seal/file-seal-claim-boundaries.md.
```

## Requirements

- Python 3, standard library only.
- Built `andna` CLI binary.
- No pip dependencies.
- No external network requests.
- Server binds to `127.0.0.1` only.
- All demo artifacts are written to a temporary directory and cleaned on exit.

## Build the CLI

Run from the repository root:

```bash
cargo build -p ffi-cli --locked --features "oqs-backend fips-integrity-stub"
```

## Run the demo

Run from the repository root:

```bash
python demo/evidence-demo/app.py
```

The app resolves the CLI in this order:

1. `ANDNA_BIN` environment variable, if set.
2. `target/debug/andna.exe`.
3. `target/debug/andna`.

If the CLI is not found, the app refuses to start and prints the exact build command.

## Run with an explicit CLI path

Git Bash / MSYS2 example:

```bash
ANDNA_BIN=target/debug/andna.exe python demo/evidence-demo/app.py
```

Linux/macOS example:

```bash
ANDNA_BIN=target/debug/andna python demo/evidence-demo/app.py
```

## Optional deterministic demo constants

The app uses deterministic software-profile demo constants through explicit `--seed-hex` and `--device-id16-hex` flags, so no profile files are created. Override them only when the repo's test fixture constants intentionally rotate.

```bash
ANDNA_DEMO_SEED_HEX=000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f ANDNA_DEMO_DEVICE_ID16_HEX=00112233445566778899aabbccddeeff python demo/evidence-demo/app.py
```

## Manual acceptance checklist

Record these results in the PR description:

- Clean flow: `Seal File` → `Verify File` → `ACCEPT` with `AUTHENTIC yes`, `UNCHANGED yes`, `AUTHORIZED yes`.
- Tamper flow: `Seal File` → `Tamper File` → `Verify File` → `REJECT` with `AUTHENTIC yes`, `UNCHANGED no`, unchanged detail `file_hash_mismatch`, `AUTHORIZED yes`.
- `Show Evidence` renders the deterministic section, runtime section, and `evidence_digest_hex`.
- `git status` remains clean of temp artifacts.
- Nothing outside `demo/evidence-demo/` changed for this branch.
- The file-seal contract script still passes.

## Contract validation

Run from the repository root:

```bash
bash scripts/file_seal_cli_contract.sh
```

Expected final line:

```text
PASS: file-seal CLI contract
```

## Scope guard

Allowed in this demo directory:

- Local UI rendering.
- `subprocess` calls to the existing `andna` CLI.
- Reading CLI exit codes.
- Reading evidence JSON for display.
- Temporary demo files in `tempfile.mkdtemp`.

Not allowed in this demo directory:

- Verification logic.
- Frame parsing for validity decisions.
- Cryptography.
- Direct R1/D0/R2 implementation shortcuts.
- Writes into the repository tree during demo execution.
- External network requests.
- Pip dependencies.
