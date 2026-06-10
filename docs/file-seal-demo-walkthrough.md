# AN-DNA File-Seal Demo Walkthrough

Status: operator walkthrough with real captured CLI output  
CLI surface: `init-sealer`, `seal-file`, `inspect-seal`, `verify-file`  
Style rule: all commands are single-line — no backslash continuations

---

## Prerequisites

Build the CLI binary (run once from the repository root):

```bash
cargo build -p ffi-cli --locked --features "oqs-backend fips-integrity-stub"
```

The binary is placed at `target/debug/andna.exe` (Windows) or `target/debug/andna` (Linux/macOS).

The contract script also builds the CLI before running, so if you run it first the binary will already exist:

```bash
bash scripts/file_seal_cli_contract.sh
```

---

## Walkthrough

The steps below use the TEST seeds from `demo/evidence-bundle-example/` — fixed values that provide no security, labeled for demo use only. Commands are issued from the repository root.

### Step 1 — Seal the file

Seal `sample.txt` into a detached sidecar. The sealer identity is provided via `--seed-hex` and `--device-id16-hex` (no profile file needed). `--registry-out` writes an authorization registry snapshot alongside the sidecar.

```
./target/debug/andna.exe seal-file demo/evidence-bundle-example/sample.txt --seed-hex 4242424242424242424242424242424242424242424242424242424242424242 --device-id16-hex d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0 --epoch 7 --out demo/evidence-bundle-example/sample.txt.andna-seal.json --content-type text/plain --registry-out demo/evidence-bundle-example/sample.registry.json
```

Actual output:

```
════════════════════════════════════════════════════════════
  AN-DNA File Seal Created
════════════════════════════════════════════════════════════
    Input file:            demo/evidence-bundle-example/sample.txt
    Seal sidecar:          demo/evidence-bundle-example/sample.txt.andna-seal.json
    Signer source:         manual seed/device flags
    Manifest hash:         7d593de014bdb124b610dbbcad8a3b18f2a07dcafc2bfc3bd5e0e1854b3f4734
    File hash:             903aba36b00c53e5464383f17b5f5b709c9c6fdea5bfab13ca89d7a0e3915040
    Frame encoding:        frame-v2-hex
    Epoch:                 7
────────────────────────────────────────────────────────────
  Scope: integrity/authenticity binding only; this does NOT encrypt the file.
    Registry:              demo/evidence-bundle-example/sample.registry.json
```

Exit code: `0`

The **manifest hash** is `SHA3-256` over the canonical manifest (filename, content type, file hash, byte length). It becomes the `ctx_hash` embedded in the signed frame, binding the specific file to the R1 identity claim.

The **file hash** is `SHA3-256` of the file bytes and is what the unchanged check compares at verification time.

**Note on determinism:** ML-DSA-44 signing is hedged (randomized nonce), so the frame bytes differ on every invocation even with the same seed and file. The manifest hash and file hash are deterministic; the signed frame is not. Re-running seal-file produces a valid but byte-different sidecar.

---

### Step 2 — Inspect the sidecar

`inspect-seal` is a structural inspection tool. It checks sidecar shape, frame length, epoch and device fields, and `ctx_hash` binding without performing full R1 cryptographic verification.

```
./target/debug/andna.exe inspect-seal demo/evidence-bundle-example/sample.txt.andna-seal.json
```

Actual output:

```
════════════════════════════════════════════════════════════
  AN-DNA Seal Inspection
════════════════════════════════════════════════════════════
    Seal sidecar:          demo/evidence-bundle-example/sample.txt.andna-seal.json
    Sidecar schema:        andna-seal-sidecar-v0
    Frame encoding:        frame-v2-hex
    Frame length:          4030
    Frame length status:   ok
────────────────────────────────────────────────────────────
    Manifest schema:       andna-seal-manifest-v0
    Manifest policy:       detached-file-integrity-v0
    Digest algorithm:      sha3-256
    File name:             sample.txt
    File size:             63
    Content type:          text/plain
    File hash:             903aba36b00c53e5464383f17b5f5b709c9c6fdea5bfab13ca89d7a0e3915040
    Manifest hash:         7d593de014bdb124b610dbbcad8a3b18f2a07dcafc2bfc3bd5e0e1854b3f4734
────────────────────────────────────────────────────────────
    Frame ctx_hash:        7d593de014bdb124b610dbbcad8a3b18f2a07dcafc2bfc3bd5e0e1854b3f4734
    ctx_hash matches:      yes
    Frame epoch:           7
    T_E epoch:             7
    device_id16:           d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0
    device_id32:           b45e300e71a68815ea06fac2fa9bb161889e9802c207a1b88b7f49782e4f85e4
────────────────────────────────────────────────────────────
  Inspection only: this does NOT verify the file or authorize the signer.
```

Exit code: `0`

Key indicators for a structurally valid sidecar:

| Field | Expected |
| --- | --- |
| `Frame length status` | `ok` |
| `ctx_hash matches` | `yes` |
| `Frame epoch` == `T_E epoch` | yes |

`ctx_hash matches: yes` confirms the manifest hash is correctly embedded in the frame. A tampered manifest would show `ctx_hash matches: no`.

`inspect-seal` does not confirm signature validity or authorization. Those require `verify-file`.

---

### Step 3 — Verify the file, produce evidence, attest the evidence

`verify-file` runs the full R1 → R2 pipeline: ML-DSA-44 signature verification, unchanged check, local authorization check, and combined decision. With `--evidence-out` it writes a stable `andna-seal-evidence-v1` record. With `--attest-profile` and `--attest-registry-out` it seals the evidence record as another artifact so later edits to the evidence file are detectable.

The verifier profile uses fixed TEST seeds passed via a profile JSON (the attester path requires a profile file; the TEST seeds are clearly labeled in the demo bundle).

```
./target/debug/andna.exe verify-file demo/evidence-bundle-example/sample.txt --seal demo/evidence-bundle-example/sample.txt.andna-seal.json --registry demo/evidence-bundle-example/sample.registry.json --evidence-out demo/evidence-bundle-example/sample.verify.json --attest-profile .andna-demo/verifier-demo-profile.json --attest-registry-out demo/evidence-bundle-example/verifier.registry.json
```

Actual output:

```
════════════════════════════════════════════════════════════
  AN-DNA File Seal Verification
════════════════════════════════════════════════════════════
    Input file:            demo/evidence-bundle-example/sample.txt
    Seal sidecar:          demo/evidence-bundle-example/sample.txt.andna-seal.json
    Registry:              demo/evidence-bundle-example/sample.registry.json
────────────────────────────────────────────────────────────
    AUTHENTIC:             yes
    UNCHANGED:             yes
    AUTHORIZED:            yes
    RESULT:                ACCEPT
────────────────────────────────────────────────────────────
    Summary:               AUTHENTIC: yes | UNCHANGED: yes | AUTHORIZED: yes
    File hash:             903aba36b00c53e5464383f17b5f5b709c9c6fdea5bfab13ca89d7a0e3915040
    Manifest hash:         7d593de014bdb124b610dbbcad8a3b18f2a07dcafc2bfc3bd5e0e1854b3f4734
    Frame ctx_hash:        7d593de014bdb124b610dbbcad8a3b18f2a07dcafc2bfc3bd5e0e1854b3f4734

Evidence written: demo/evidence-bundle-example/sample.verify.json
    Evidence digest:       3ff8de2b4a467f591191e01086569d4226f90f1a8797c3ab035a492fff1c8a7c
    Evidence attestation:  demo/evidence-bundle-example/sample.verify.json.andna-seal.json
    Attester source:       profile: .andna-demo/verifier-demo-profile.json
    Attest registry:       demo/evidence-bundle-example/verifier.registry.json
  Attestation scope: authenticity of the evidence record under the
  verifier software-profile; verify it with `andna verify-file`.
```

Exit code: `0`

The three verdicts (`AUTHENTIC`, `UNCHANGED`, `AUTHORIZED`) are separated. `RESULT: ACCEPT` requires all three to be positive. A tampered file would give `UNCHANGED: no` without changing `AUTHENTIC`.

The **evidence digest** (`3ff8de2b...`) is `SHA3-256` over the canonical encoding of the deterministic section. It covers only the decision fields, not the runtime paths or timestamp.

---

### Step 4 — Verify the evidence attestation

The evidence file (`sample.verify.json`) was sealed as another artifact during step 3. Verifying it confirms the evidence record itself has not been edited since attestation.

```
./target/debug/andna.exe verify-file demo/evidence-bundle-example/sample.verify.json --seal demo/evidence-bundle-example/sample.verify.json.andna-seal.json --registry demo/evidence-bundle-example/verifier.registry.json
```

Actual output:

```
════════════════════════════════════════════════════════════
  AN-DNA File Seal Verification
════════════════════════════════════════════════════════════
    Input file:            demo/evidence-bundle-example/sample.verify.json
    Seal sidecar:          demo/evidence-bundle-example/sample.verify.json.andna-seal.json
    Registry:              demo/evidence-bundle-example/verifier.registry.json
────────────────────────────────────────────────────────────
    AUTHENTIC:             yes
    UNCHANGED:             yes
    AUTHORIZED:            yes
    RESULT:                ACCEPT
────────────────────────────────────────────────────────────
    Summary:               AUTHENTIC: yes | UNCHANGED: yes | AUTHORIZED: yes
    File hash:             8803f1affe7dfab350357e9a7b61968ed932c4b5ddcbf896e0f9416e42a64339
    Manifest hash:         e67af1b217a9fec39a0ca4aaf7d409d63a73d9e75d3138ccd59bcd46a529aa4e
    Frame ctx_hash:        e67af1b217a9fec39a0ca4aaf7d409d63a73d9e75d3138ccd59bcd46a529aa4e
```

Exit code: `0`

The evidence file is treated as an ordinary sealed artifact. If any deterministic field in the evidence record were edited, the `UNCHANGED` check would fail: the file's `SHA3-256` would no longer match the `ctx_hash` in the attestation frame.

---

## Evidence record structure

The committed `demo/evidence-bundle-example/sample.verify.json` shows the evidence v1 structure:

```json
{
  "schema_version": "andna-seal-evidence-v1",
  "deterministic": {
    "result": "ACCEPT",
    "authentic": true,
    "unchanged": "yes",
    "unchanged_detail": null,
    "authorized": "yes",
    "reason_code": "registry_entry_valid",
    "verify_error": null,
    "file_hash_hex": "903aba36b00c53e5464383f17b5f5b709c9c6fdea5bfab13ca89d7a0e3915040",
    "frame_hash_hex": "d40a7c348f30cd12423e4e7c4120a31d77d3885273d4ab9d3bef01f65b55d18f",
    "manifest_hash_hex": "7d593de014bdb124b610dbbcad8a3b18f2a07dcafc2bfc3bd5e0e1854b3f4734",
    "frame_ctx_hash_hex": "7d593de014bdb124b610dbbcad8a3b18f2a07dcafc2bfc3bd5e0e1854b3f4734",
    "epoch": 7,
    "device_id32_hex": "b45e300e71a68815ea06fac2fa9bb161889e9802c207a1b88b7f49782e4f85e4",
    "te_hash_hex": "ad80b8576ea75bd7c94d9d4f141b765387e7f626249b1b0027404f8533cb05d9...",
    "attestation_status": "NONE_SOFTWARE_PROFILE",
    "registry_policy_version": "andna-seal-cli-registry-v0",
    "entry_policy_version": "andna-seal-cli-device-v0",
    "snapshot_seq": 1,
    "as_of_unix_ms": 1781115161136,
    "registry_snapshot_hash_hex": "a6881afd9b17785250c51d6c355e48ecb25e1131fd8f0e3db4cff67eda88d9e7",
    "policy_digest_hex": "53a4e5e55b599fe410ce9dea832c098270e12102e62582fadf5db70f9b03a009"
  },
  "evidence_digest_hex": "3ff8de2b4a467f591191e01086569d4226f90f1a8797c3ab035a492fff1c8a7c",
  "runtime": {
    "file_path": "demo/evidence-bundle-example/sample.txt",
    "seal_path": "demo/evidence-bundle-example/sample.txt.andna-seal.json",
    "registry_path": "demo/evidence-bundle-example/sample.registry.json",
    "tool_version": "andna 0.1.0",
    "verified_at_unix_ms": 1781115161673
  },
  "display_summary": "AUTHENTIC: yes | UNCHANGED: yes | AUTHORIZED: yes"
}
```

The `deterministic` section is the replayable core. `evidence_digest_hex` is `SHA3-256` over its canonical encoding. The `runtime` section (paths, version, timestamp) is recorded but excluded from the digest.

**`te_hash_hex`** is `SHAKE256-64` over `(pk_epoch ‖ epoch ‖ device_id16)` — the R1 epoch-key binding. This is a 64-byte SHAKE256 output (128 hex chars). It is distinct from the `SHA3-256` hashes used for the manifest, file, frame, and evidence digest.

---

## Replay property

Running `verify-file` again with the same committed `sample.txt`, `sample.txt.andna-seal.json`, and `sample.registry.json` produces an identical `deterministic` section and the same `evidence_digest_hex`. This is the replay property: the deterministic section is a pure function of the bundle, file bytes, and registry snapshot.

The `regen.sh` script verifies this automatically:

```bash
bash demo/evidence-bundle-example/regen.sh
```

Expected final line: `PASS: regen.sh default mode`

---

## Operator contract validation

```bash
bash scripts/file_seal_cli_contract.sh
```

Expected final line: `PASS: file-seal CLI contract`

The contract script covers the full operator surface including tamper cases, empty-registry rejection, and forged-evidence rejection.
