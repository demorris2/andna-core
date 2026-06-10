# AN-DNA File-Seal Claim Boundaries

Status: required public-language boundary for the file-seal MVP

## Approved short claim

AN-DNA can seal a file into a detached sidecar, bind the manifest hash into an R1 verification context, inspect the sidecar structure, verify authenticity, check that the file is unchanged, evaluate local authorization, and emit a replayable `ACCEPT` or `REJECT` decision.

## What the current file-seal lane demonstrates

The current CI-backed file-seal lane demonstrates:

- local software-profile initialization for demo/MVP use
- detached file sidecar creation
- sidecar inspection
- manifest-to-frame hash binding
- R1 authenticity verification
- file unchanged check
- R2 local authorization check
- stable evidence JSON under `andna-seal-evidence-v1`
- deterministic evidence digest over replayable decision fields
- runtime field exclusion from the evidence digest
- evidence attestation using the existing file-seal path
- rejection of forged evidence under an existing attestation
- rejection of tampered files, empty registries, tampered manifests, malformed frames, and missing inputs

## What this is not

Do not claim that the current file-seal MVP is:

- hardware-backed custody
- clone-resistant identity
- a physical badge security system
- enterprise IAM
- file encryption
- a FIPS-validated module
- an ACVP-tested cryptographic module
- a replacement for Sigstore, SLSA, TUF, or in-toto
- production-ready key management
- proof that a human personally approved an artifact
- proof that a file is safe, malware-free, or semantically correct

## Correct framing

Use this framing:

> AN-DNA File-Seal is a deterministic trust-evidence layer for consequential files and artifacts. It separates authenticity, unchanged state, and authorization, then records the combined decision in a replayable evidence contract.

Do not frame it as:

> AN-DNA encrypts files, replaces software supply-chain tooling, provides hardware custody, or proves real-world author intent.

## Software-profile sealer boundary

The current `init-sealer` profile is demo/MVP scoped.

Allowed statements:

- It generates local seed material.
- It generates local device identity material.
- It writes a local software-profile JSON file.
- It enables local file-seal and verifier demonstrations.
- It must be ignored by Git and protected by the operator.

Disallowed statements:

- It is hardware-backed.
- It prevents cloning.
- It proves physical possession.
- It is production IAM.
- It is a substitute for a hardware security module.
- It is enterprise key custody.

## Evidence-attestation boundary

The evidence-attestation flow seals the evidence record as another artifact. This is useful because it lets an operator show that a specific evidence file later remained unchanged.

Allowed statement:

> AN-DNA can seal and verify its own evidence output so later edits to the evidence file are detected as file tamper.

Do not overstate this as:

> AN-DNA makes evidence impossible to forge.

A party with signing material can create new evidence or new attestations. The current value is explicit replayability, digest consistency, and tamper detection against a specific sealed evidence artifact.

## Inspect command boundary

`inspect-seal` is a structural inspection tool. It checks sidecar shape, frame length, epoch/device fields, and manifest hash binding.

Do not claim that `inspect-seal` alone verifies authenticity or authorization. Full verification requires `verify-file` with the relevant file bytes and registry snapshot.

## Product language

Preferred:

- replayable evidence
- deterministic verification
- explicit decision separation
- file/object trust envelope
- local authorization snapshot
- evidence digest
- operator-verifiable decision record

Avoid:

- unbreakable
- impossible to forge
- military-grade
- FIPS-ready
- quantum-proof identity
- trustless proof of human intent
- replaces existing supply-chain standards

## Current market positioning

AN-DNA should be positioned as a complementary evidence layer, not a replacement layer.

It can sit beside existing signing, provenance, and audit systems by answering:

```text
What was checked?
What did the verifier decide?
Was the file unchanged?
Was the identity authorized at that registry snapshot?
Can the decision be replayed later?
```

That is the current credible wedge.
