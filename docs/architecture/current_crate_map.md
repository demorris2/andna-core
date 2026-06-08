# AN-DNA Current Crate Map

## Purpose

This document describes the current AN-DNA Rust workspace structure and the intended responsibility of each crate.

The goal is to keep the architecture clean as the project expands from R1 verification into D0 identity derivation, R2 policy authorization, file sealing, and future access-control workflows.

## Workspace Overview

Current workspace layers:

```text
contracts
codec
transcript
mldsa44
core
andna-d0
ffi
audit
andna-r2
pipeline
andna-seal
ffi_cli
xtask
contracts_codegen
```

The architecture is intentionally layered.

Lower layers define byte contracts and cryptographic verification. Higher layers compose those facts into authorization decisions and user-facing workflows.

## Layer Summary

```text
contracts       shared constants and byte-layout definitions
codec           frame packing and unpacking
transcript      transcript construction and hash bindings
mldsa44         ML-DSA-44 verification interface
core            R1 verification engine
andna-d0        prover-side deterministic identity derivation
andna-r2        local authorization policy engine
pipeline        R1 verification plus R2 authorization composition
andna-seal      file/object seal layer
ffi             FFI boundary and Approved Mode initialization
audit           audit hash chain and evidence validation
ffi_cli         operator-facing CLI
xtask           build and integrity helper tasks
contracts_codegen contract/code generation helper
```

## contracts

Path:

```text
crates/contracts
```

Role:

```text
Single source of truth for shared constants, byte lengths, offsets, and contract values.
```

Allowed responsibilities:

```text
define frame lengths
define transcript offsets
define T_E layout constants
define digest and field lengths
provide stable shared constants across crates
```

Not allowed:

```text
cryptographic verification
policy decisions
file sealing
runtime authorization
I/O
```

## codec

Path:

```text
crates/codec
```

Role:

```text
Frame packing and unpacking.
```

Allowed responsibilities:

```text
pack Frame v2
parse Frame v2
validate structural frame length
extract frame sections
roundtrip frame bytes
```

Not allowed:

```text
signature verification
policy authorization
D0 derivation
file hashing
access-control policy
```

## transcript

Path:

```text
crates/transcript
```

Role:

```text
Transcript construction and hash binding helpers.
```

Allowed responsibilities:

```text
construct mu_pre
derive mu from mu_pre
derive pk_hash
derive device_id32 from device_id16
check transcript-level binding relationships
provide ctx_hash binding support
```

Not allowed:

```text
file manifest semantics
registry authorization
audit-chain validation
physical access-control logic
```

## mldsa44

Path:

```text
crates/mldsa44
```

Role:

```text
ML-DSA-44 verification interface for R1.
```

Allowed responsibilities:

```text
call ML-DSA verification backend
enforce public key and signature lengths
run verification tests
hold ACVP-style signature verification tests
```

Not allowed:

```text
D0 seeded key generation
R2 policy
file sealing
authorization decisions
```

Notes:

```text
R1 verification remains liboqs-backed.
D0 seeded key generation uses a separate fips204 path.
The dual-backend boundary is intentional.
```

## core

Path:

```text
crates/core
```

Role:

```text
R1 verification engine.
```

Allowed responsibilities:

```text
verify Frame v2
verify R1 transcript bindings
verify pk_hash binding
verify epoch correlation
verify device-id duality
call ML-DSA verification
return CRYPTO_ACCEPT / CRYPTO_REJECT-style results
```

Not allowed:

```text
R2 authorization
registry policy
file seal semantics
D0 state mutation
access-control policy
```

Important boundary:

```text
A valid R1 signature does not mean authorized.
R1 only verifies cryptographic acceptability.
R2 decides authorization.
```

## andna-d0

Path:

```text
crates/andna-d0
```

Role:

```text
Prover-side deterministic identity and epoch-key derivation.
```

Allowed responsibilities:

```text
derive D0 state
ratchet state across epochs
derive seeded ML-DSA-44 key material
build T_E
produce test vectors
support D0 to R1 interop testing
```

Not allowed:

```text
R1 verification
R2 authorization
file seal policy
access-control policy
liboqs dependency in normal D0 path
```

Important boundary:

```text
andna-d0 uses fips204 for seeded ML-DSA-44 key generation.
R1 verification remains liboqs-backed.
andna-d0 should remain isolated from oqs/liboqs.
```

## andna-r2

Path:

```text
crates/andna-r2
```

Role:

```text
Local authorization policy engine.
```

Allowed responsibilities:

```text
load local registry snapshots
evaluate verified facts
authorize or reject known identities
detect revoked credentials
detect frozen lineage
detect recovery hold
detect stale epoch
detect unauthorized T_E hash
produce policy_digest
produce snapshot_hash
```

Not allowed:

```text
cryptographic verification
ML-DSA verification
frame parsing
D0 derivation
file hashing
```

Important boundary:

```text
andna-r2 must remain crypto-backend-free.
R2 consumes verified facts; it does not verify signatures.
```

## pipeline

Path:

```text
crates/pipeline
```

Role:

```text
Composition layer from R1 verification to R2 authorization.
```

Allowed responsibilities:

```text
call R1 verification
extract verified facts
call R2 authorization
produce combined decision
serialize combined decision evidence
ensure R2 is NOT_EVALUATED if R1 rejects
```

Not allowed:

```text
implementing a second verifier
changing R1 semantics
changing R2 policy semantics
D0 derivation
file-seal manifest hashing
```

Important boundary:

```text
The pipeline composes decisions. It does not redefine them.
```

## andna-seal

Path:

```text
crates/andna-seal
```

Role:

```text
Detached file/object seal layer.
```

Allowed responsibilities:

```text
hash file bytes
build deterministic file manifest
hash canonical manifest
place manifest_hash into ctx_hash
seal file with software-profile signer
produce detached sidecar
verify sidecar
check R1 authenticity through pipeline
check file unchanged status
check R2 authorization
return AUTHENTIC / UNCHANGED / AUTHORIZED result
```

Not allowed:

```text
encryption
malware detection
hardware identity claims
new R1 verifier
new R2 policy engine
production credential custody
```

Important boundary:

```text
andna-seal proves object integrity/authenticity/authorization evidence.
It does not encrypt the file.
It does not prove hardware custody.
```

## ffi

Path:

```text
crates/ffi
```

Role:

```text
FFI boundary and Approved Mode initialization.
```

Allowed responsibilities:

```text
export C-compatible functions
perform power-up self-tests
run KATs
run HMAC software-integrity check
enforce initialization guard
provide FFI access to R1 operations
```

Not allowed:

```text
R2 policy authorization
D0 state mutation
file-seal CLI logic
GUI logic
```

Important boundary:

```text
The FFI lane is part of the R1/Approved Mode boundary.
File-seal CLI may use Rust library calls directly where appropriate.
```

## audit

Path:

```text
crates/audit
```

Role:

```text
Audit chain and evidence validation.
```

Allowed responsibilities:

```text
write audit JSONL
validate audit hash chains
detect tampering
detect deletion
detect duplication
detect reordering
export evidence artifacts
```

Not allowed:

```text
signature verification
policy authorization
D0 derivation
file hashing
```

## ffi_cli

Path:

```text
ffi_cli
```

Role:

```text
Operator-facing command-line interface.
```

Allowed responsibilities:

```text
parse commands
read and write files
call R1, replay, export, and seal APIs
print user-facing results
run local demo workflows
```

Not allowed:

```text
reimplement R1 verification
reimplement R2 policy
reimplement file-seal hashing
reimplement D0 derivation
carry business logic that belongs in crates
```

CLI design rule:

```text
The CLI orchestrates. Rust crates decide.
```

## xtask

Path:

```text
xtask
```

Role:

```text
Build and maintenance helper commands.
```

Allowed responsibilities:

```text
generate integrity reference files
support reproducibility helpers
support local build workflows
```

Not allowed:

```text
runtime authorization
R1 verification decisions
R2 policy decisions
file-seal verification
```

## contracts_codegen

Path:

```text
contracts_codegen
```

Role:

```text
Contract/code generation helper.
```

Allowed responsibilities:

```text
derive generated constants or headers from contract definitions
support build-time contract consistency
```

Not allowed:

```text
runtime verification
policy authorization
file sealing
```

## Python / GUI Boundary

Path:

```text
python/
```

Current status:

```text
Legacy/demo layer.
```

The Python and GUI code should not be considered authoritative.

Allowed future responsibilities:

```text
display verification results
wrap CLI commands
provide local demo dashboard
orchestrate file selection
show evidence JSON
show audit trail
```

Not allowed:

```text
reimplement R1 verification
reimplement frame parsing
reimplement transcript hashing
reimplement R2 policy
reimplement file-seal verification
```

Rule:

```text
Python/UI may display and orchestrate.
Rust remains authoritative.
```

## Access-Control Direction

The current file-seal workflow is the first practical object-binding workflow.

The next access-control layer should follow the same architecture:

```text
AccessRequest manifest
→ request hash
→ signed R1 ctx_hash
→ R1 verification
→ R2 authorization
→ replayable access decision
```

Future access-control crates or modules should preserve the existing boundaries:

```text
D0 derives credential lineage.
R1 verifies the signed request.
R2 decides whether access is authorized.
Audit records the decision.
CLI/UI displays the result.
```

## Engineering Rules

### Rule 1 — Do not create parallel verifiers

No crate should recreate R1 verification logic unless it is explicitly part of `core` or `mldsa44`.

### Rule 2 — Do not authorize on signature alone

A valid signature means cryptographic acceptance, not authorization.

### Rule 3 — Keep R2 crypto-free

R2 should consume verified facts. It should not depend on liboqs or ML-DSA backends.

### Rule 4 — Keep D0 prover-side

D0 derives identity/key material. R1 verifies. Do not blur those roles.

### Rule 5 — Keep CLI thin

The CLI should call crate APIs and print results. It should not own core decision logic.

### Rule 6 — Be precise about claims

Current system can claim:

```text
authenticity verification
file unchanged checks
local policy authorization
replayable decision evidence
post-quantum signature verification path
```

Current system should not claim:

```text
encryption
hardware identity
clone resistance
malware detection
enterprise IAM replacement
physical access-control production readiness
```

## Current Practical Workflow

The current practical workflow is:

```text
andna seal-file <file> ...
andna verify-file <file> ...
```

Expected result:

```text
AUTHENTIC: yes
UNCHANGED: yes
AUTHORIZED: yes
RESULT: ACCEPT
```

This workflow proves the local object-decision chain and prepares the path for access-control envelopes.
