# AN-DNA File Seal CLI Demo

## Purpose

This demo shows the first practical AN-DNA operator workflow.

The workflow seals a local file, creates a detached AN-DNA sidecar, creates a matching local registry, and verifies the file through the current AN-DNA decision chain.

The result is shown as:

```text
AUTHENTIC
UNCHANGED
AUTHORIZED
RESULT
```

This demo is intentionally local. It does not require a remote service.

## What This Demonstrates

This workflow demonstrates that AN-DNA can:

```text
hash a real file
build a deterministic file manifest
bind the manifest hash into the signed R1 context hash
verify the signed frame through R1
check that the file is unchanged
authorize the signer through R2
emit user-readable decision evidence
```

The successful result is:

```text
AUTHENTIC: yes
UNCHANGED: yes
AUTHORIZED: yes
RESULT: ACCEPT
```

## What This Does Not Demonstrate

This workflow does not claim:

```text
encryption
malware detection
hardware identity
clone resistance
physical access-control readiness
enterprise IAM replacement
```

The file is not encrypted. The current signer is a software-profile signer. It proves possession of the signing seed/key for this local workflow, not hardware custody.

## Command Summary

Seal a file:

```text
andna seal-file <file> \
  --out <file>.andna-seal.json \
  --seed-hex <64 hex chars> \
  --device-id16-hex <32 hex chars> \
  --epoch <number> \
  --content-type <mime> \
  --registry-out <registry.json>
```

Verify a file:

```text
andna verify-file <file> \
  --seal <file>.andna-seal.json \
  --registry <registry.json> \
  --evidence-out <verify-result.json>
```

## Demo Setup

From the repo root:

```bash
cd /c/andna-core
```

Create a sample file:

```bash
echo "hello AN-DNA file seal" > sample.txt
```

Set a demo seed and device ID:

```bash
SEED_HEX=4242424242424242424242424242424242424242424242424242424242424242
DEVICE_ID16_HEX=c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0
```

These values are for demo use only.

## Seal the File

Run:

```bash
cargo run -p ffi-cli --locked \
  --features "oqs-backend fips-integrity-stub" \
  -- seal-file sample.txt \
     --out sample.txt.andna-seal.json \
     --seed-hex "$SEED_HEX" \
     --device-id16-hex "$DEVICE_ID16_HEX" \
     --epoch 7 \
     --content-type text/plain \
     --registry-out sample.registry.json
```

Expected output shape:

```text
════════════════════════════════════════════════════════════
  AN-DNA File Seal Created
════════════════════════════════════════════════════════════
    Input file:            sample.txt
    Seal sidecar:          sample.txt.andna-seal.json
    Manifest hash:         <sha3-256 manifest hash>
    File hash:             <sha3-256 file hash>
    Frame encoding:        frame-v2-hex
    Epoch:                 7
────────────────────────────────────────────────────────────
  Scope: integrity/authenticity binding only; this does NOT encrypt the file.
    Registry:              sample.registry.json
```

Files created:

```text
sample.txt.andna-seal.json
sample.registry.json
```

## Verify the File

Run:

```bash
cargo run -p ffi-cli --locked \
  --features "oqs-backend fips-integrity-stub" \
  -- verify-file sample.txt \
     --seal sample.txt.andna-seal.json \
     --registry sample.registry.json \
     --evidence-out sample.verify.json
```

Expected output:

```text
════════════════════════════════════════════════════════════
  AN-DNA File Seal Verification
════════════════════════════════════════════════════════════
    Input file:            sample.txt
    Seal sidecar:          sample.txt.andna-seal.json
    Registry:              sample.registry.json
────────────────────────────────────────────────────────────
    AUTHENTIC:             yes
    UNCHANGED:             yes
    AUTHORIZED:            yes
    RESULT:                ACCEPT
────────────────────────────────────────────────────────────
    Summary:               AUTHENTIC: yes | UNCHANGED: yes | AUTHORIZED: yes
    File hash:             <sha3-256 file hash>
    Manifest hash:         <sha3-256 manifest hash>
    Frame ctx_hash:        <same manifest hash>

Evidence written: sample.verify.json
```

The key check is:

```text
Manifest hash == Frame ctx_hash
```

That means the file manifest is bound into the signed R1 context.

## Negative Test: Tampered File

Copy and modify the file:

```bash
cp sample.txt sample.tampered.txt
echo "tamper" >> sample.tampered.txt
```

Verify the tampered file against the original seal:

```bash
cargo run -p ffi-cli --locked \
  --features "oqs-backend fips-integrity-stub" \
  -- verify-file sample.tampered.txt \
     --seal sample.txt.andna-seal.json \
     --registry sample.registry.json
```

Expected result:

```text
AUTHENTIC: yes
UNCHANGED: no
AUTHORIZED: yes
RESULT: REJECT
```

Interpretation:

```text
The seal frame is authentic.
The signer is authorized.
But the file bytes no longer match the sealed manifest.
Therefore the final result is REJECT.
```

## Negative Test: Unauthorized Registry

Create an empty registry:

```bash
cat > empty.registry.json <<'EOF'
{
  "snapshot_seq": 1,
  "as_of_unix_ms": 1700000000000,
  "policy_version": "empty-registry-v0",
  "entries": []
}
EOF
```

Verify the original file against the empty registry:

```bash
cargo run -p ffi-cli --locked \
  --features "oqs-backend fips-integrity-stub" \
  -- verify-file sample.txt \
     --seal sample.txt.andna-seal.json \
     --registry empty.registry.json
```

Expected result:

```text
AUTHENTIC: yes
UNCHANGED: yes
AUTHORIZED: no
RESULT: REJECT
```

Interpretation:

```text
The seal frame is authentic.
The file is unchanged.
But the registry does not authorize the signer.
Therefore the final result is REJECT.
```

## Cleanup

Remove demo artifacts:

```bash
rm -f sample.txt \
      sample.tampered.txt \
      sample.txt.andna-seal.json \
      sample.registry.json \
      sample.verify.json \
      empty.registry.json
```

## Access-Control Interpretation

This file-seal workflow is the first object-based version of the broader AN-DNA access-control model.

For files, AN-DNA asks:

```text
Is this file seal authentic?
Is this file unchanged?
Is the sealing identity authorized?
```

For future access requests, AN-DNA will ask:

```text
Is this access request authentic?
Is the credential current?
Is the requester authorized for the resource/action?
Can the access decision be replayed later?
```

The structure is the same:

```text
object or request
→ manifest/context hash
→ signed R1 frame
→ R1 verification
→ R2 authorization
→ replayable decision evidence
```

## Product Translation

Plain-language description:

```text
AN-DNA can seal a file and later verify whether it is authentic, unchanged, and authorized.
```

Access-control translation:

```text
AN-DNA can turn a file, credential, device, or access request into a replayable authorization decision.
```

## Profile-Backed Demo Workflow

The recommended local demo now uses a reusable software-profile sealer.

This avoids passing raw seed and device ID values on every `seal-file` command.

### Step 1 — Create a Local Sealer Profile

```bash
cd /c/andna-core

rm -rf .andna
rm -f sample.txt sample.tampered.txt sample.txt.andna-seal.json sample.registry.json sample.verify.json empty.registry.json

cargo run -p ffi-cli --locked \
  --features "oqs-backend fips-integrity-stub" \
  -- init-sealer \
     --profile .andna/sealer-profile.json \
     --epoch 7
```

Expected output:

```text
════════════════════════════════════════════════════════════
  AN-DNA Software-Profile Sealer Created
════════════════════════════════════════════════════════════
    Profile:               .andna/sealer-profile.json
    Profile type:          software-profile
    Epoch:                 7
────────────────────────────────────────────────────────────
  Warning: profile contains seed material. Do not commit or share.
  Scope: software-profile only; not hardware custody or clone resistance.
```

The profile is local demo credential material.

Do not commit it.

### Step 2 — Create a Sample File

```bash
echo "hello AN-DNA profile-backed file seal" > sample.txt
```

### Step 3 — Seal the File Using the Profile

```bash
cargo run -p ffi-cli --locked \
  --features "oqs-backend fips-integrity-stub" \
  -- seal-file sample.txt \
     --profile .andna/sealer-profile.json \
     --out sample.txt.andna-seal.json \
     --content-type text/plain \
     --registry-out sample.registry.json
```

Expected output shape:

```text
════════════════════════════════════════════════════════════
  AN-DNA File Seal Created
════════════════════════════════════════════════════════════
    Input file:            sample.txt
    Seal sidecar:          sample.txt.andna-seal.json
    Signer source:         profile: .andna/sealer-profile.json
    Manifest hash:         <sha3-256 manifest hash>
    File hash:             <sha3-256 file hash>
    Frame encoding:        frame-v2-hex
    Epoch:                 7
────────────────────────────────────────────────────────────
  Scope: integrity/authenticity binding only; this does NOT encrypt the file.
    Registry:              sample.registry.json
```

This creates:

```text
sample.txt.andna-seal.json
sample.registry.json
```

The seal sidecar contains the manifest and signed frame.

The registry file authorizes the sealing identity for this local demo.

### Step 4 — Verify the File

```bash
cargo run -p ffi-cli --locked \
  --features "oqs-backend fips-integrity-stub" \
  -- verify-file sample.txt \
     --seal sample.txt.andna-seal.json \
     --registry sample.registry.json \
     --evidence-out sample.verify.json
```

Expected output:

```text
════════════════════════════════════════════════════════════
  AN-DNA File Seal Verification
════════════════════════════════════════════════════════════
    Input file:            sample.txt
    Seal sidecar:          sample.txt.andna-seal.json
    Registry:              sample.registry.json
────────────────────────────────────────────────────────────
    AUTHENTIC:             yes
    UNCHANGED:             yes
    AUTHORIZED:            yes
    RESULT:                ACCEPT
────────────────────────────────────────────────────────────
    Summary:               AUTHENTIC: yes | UNCHANGED: yes | AUTHORIZED: yes
    File hash:             <sha3-256 file hash>
    Manifest hash:         <sha3-256 manifest hash>
    Frame ctx_hash:        <same manifest hash>

Evidence written: sample.verify.json
```

The key proof is:

```text
Manifest hash == Frame ctx_hash
```

This means the file manifest is bound into the signed R1 frame.

## Negative Test: Tampered File

```bash
cp sample.txt sample.tampered.txt
echo "tamper" >> sample.tampered.txt

cargo run -p ffi-cli --locked \
  --features "oqs-backend fips-integrity-stub" \
  -- verify-file sample.tampered.txt \
     --seal sample.txt.andna-seal.json \
     --registry sample.registry.json

echo $?
```

Expected result:

```text
AUTHENTIC: yes
UNCHANGED: no
AUTHORIZED: yes
RESULT: REJECT
```

Expected exit code:

```text
1
```

Interpretation:

```text
The signed frame is authentic.
The signer is authorized.
The file bytes do not match the sealed manifest.
The final decision is REJECT.
```

## Negative Test: Unauthorized Registry

```bash
cat > empty.registry.json <<'EOF'
{
  "snapshot_seq": 1,
  "as_of_unix_ms": 1700000000000,
  "policy_version": "empty-registry-v0",
  "entries": []
}
EOF

cargo run -p ffi-cli --locked \
  --features "oqs-backend fips-integrity-stub" \
  -- verify-file sample.txt \
     --seal sample.txt.andna-seal.json \
     --registry empty.registry.json

echo $?
```

Expected result:

```text
AUTHENTIC: yes
UNCHANGED: yes
AUTHORIZED: no
RESULT: REJECT
```

Expected exit code:

```text
1
```

Interpretation:

```text
The signed frame is authentic.
The file is unchanged.
The registry does not authorize the signer.
The final decision is REJECT.
```

## Cleanup

```bash
rm -rf .andna
rm -f sample.txt \
      sample.tampered.txt \
      sample.txt.andna-seal.json \
      sample.registry.json \
      sample.verify.json \
      empty.registry.json
```

## Current Demo Claim

This demo proves:

```text
AN-DNA can create a local software-profile sealer, seal a file, bind the file manifest into a signed R1 frame, verify file integrity, check R2 authorization, and emit replayable evidence.
```

This is the first complete local operator workflow.
