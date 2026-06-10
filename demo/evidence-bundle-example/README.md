# AN-DNA Evidence Bundle Example

This directory contains a committed, verifiable example of the AN-DNA file-seal evidence v1 workflow.

## What is in this bundle

| File | Description |
| --- | --- |
| `sample.txt` | The sealed file |
| `sample.txt.andna-seal.json` | Detached seal sidecar binding the file to an R1 signed frame |
| `sample.registry.json` | Registry snapshot used for sealing and authorization |
| `sample.verify.json` | Evidence record produced by `verify-file` (schema: `andna-seal-evidence-v1`) |
| `sample.verify.json.andna-seal.json` | Attestation seal over the evidence record |
| `verifier.registry.json` | Registry snapshot for the evidence attestation |
| `regen.sh` | Verification and regeneration script |

## TEST SEED notice

**The seeds in this bundle are fixed TEST values. They provide no security and must never be used outside of demonstration contexts.**

Sealer identity: `seed = 0x42 × 32`, `device_id16 = 0xd0 × 16`, `epoch 7`
Verifier identity: `seed = 0xa5 × 32`, `device_id16 = 0xe3 × 16`, `epoch 3`

## Non-secret artifacts

Registries, sidecars, and evidence records are non-secret by design. The only secret in the real system is profile seed material. This bundle does not contain profile JSON files — the fixed TEST seeds above are embedded only in `regen.sh` for the `--from-scratch` mode.

## Running the verification script

### Default mode (recommended): verify and confirm replay property

```bash
bash demo/evidence-bundle-example/regen.sh
```

Default mode:

1. Runs `verify-file` on `sample.txt` against the committed seal and registry — expects `RESULT: ACCEPT`.
2. Runs `verify-file` on `sample.verify.json` against the committed attestation — expects `RESULT: ACCEPT`.
3. Produces a fresh evidence record in a temp directory, compares its `deterministic` section and `evidence_digest_hex` against the committed `sample.verify.json` — expects an exact match. This demonstrates the replay property: the same bundle, file bytes, and registry snapshot always produce the same deterministic evidence output.

### From-scratch mode: regenerate all artifacts

```bash
bash demo/evidence-bundle-example/regen.sh --from-scratch
```

From-scratch mode regenerates all artifacts using the fixed TEST seeds. The new artifacts are **valid but byte-different** from the committed ones. This is expected and inherent, not a defect:

- ML-DSA-44 signing is hedged (randomized nonce), so frame bytes differ on every signing call even with the same seed and message.
- `--registry-out` stamps `as_of_unix_ms` with the current time, so the registry hash and the deterministic section's `as_of_unix_ms` change.

After from-scratch regeneration, both file seal and evidence attestation still verify as `RESULT: ACCEPT`, but the `evidence_digest_hex` will differ from the committed baseline.

## Architecture note

This bundle is evidence for the file-seal CLI layer. It does not contain verification logic. The `regen.sh` script invokes the `andna` CLI binary and inspects exit codes and evidence JSON — it performs no cryptographic operations directly. The CLI (`ffi_cli/`) is the sole authoritative engine.

## Build the CLI (if needed)

```bash
cargo build -p ffi-cli --locked --features "oqs-backend fips-integrity-stub"
```

The script resolves the binary via `ANDNA_BIN` environment variable, then `target/debug/andna.exe` (Windows), then `target/debug/andna` (Linux/macOS). If none is found it prints the build command and exits with code 2.
