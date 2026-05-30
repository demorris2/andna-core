# AN-DNA R1 Threat Model — Verifier Boundary

**Document status:** Draft
**Version:** 1.0.0
**Date:** 2026-05-30
**Maintainer:** Darrell Morris Jr. — ArcNeura
**Scope:** AN-DNA R1 verifier implementation and proof lane
**Boundary type:** Verifier-only threat model
**Current implementation focus:** `andna-core`, `andna-ffi`, the Rust CLI proof
path, deterministic evidence export, and the Docker/HostB proof lane

---

## 1. Purpose

This document defines the threat model for the AN-DNA R1 verifier
implementation. The purpose of AN-DNA R1 is to verify structured
authentication frames, produce deterministic ACCEPT/REJECT decisions, and
export replayable evidence showing how those decisions were reached.

This document is intentionally scoped to the verifier side of the system. It
does not claim to validate the prover-side D0 epoch-witness bridge, device
identity derivation, hardware root of trust, or genesis-polynomial custody.

The goal is to make the verifier's security boundary explicit: what it
defends, what it assumes, what it cannot know, and what remains future work.

---

## 2. System Boundary

### 2.1 In Scope

The in-scope verifier boundary includes:

- Verification of packed AN-DNA frame v2 inputs.
- Parsing and validation of `mu_pre`, `T_E`, and ML-DSA-44 signature material.
- Public-verifier ML-DSA-44 signature verification through the Rust/liboqs path.
- Structural directive checks, including:
  - frame length enforcement,
  - domain separator validation,
  - `mu_pre` version validation,
  - epoch correlation,
  - device ID derivation check,
  - public-key hash binding.
- Power-up self-test behavior for the FFI module, including:
  - HMAC-SHA-256 CAST,
  - SHAKE256 KAT,
  - ML-DSA-44 ACVP-derived KAT,
  - Path A′ software integrity check.
- Deterministic verification logging.
- Rust authoritative audit chain.
- Evidence bundle export.
- Audit-chain validation for baseline, tamper, reordering, duplication, and
  deletion cases.
- Docker/HostB proof lane for reproducibility and regression validation.

### 2.2 Out of Scope

The following are explicitly out of scope for this verifier-only threat model:

- Prover-side D0 epoch-witness bridge.
- Genesis polynomial generation, storage, custody, rotation, or recovery.
- Device-side key derivation.
- Device-side ML-DSA-44 signing implementation.
- Hardware root-of-trust integration.
- TPM 2.0, TrustZone, secure enclave, or secure element attestation.
- Registry design beyond verifier evidence export and audit-chain validation.
- Behavioral legitimacy or user-intent detection.
- Network transport security.
- Authorization policy.
- Revocation policy.
- Production deployment hardening outside the verifier artifact bundle.
- Formal FIPS 140-3 validation status.
- ACVP/CAVP certificate issuance.

---

## 3. Security Objective

The verifier's primary security objective is:

> Given a structured AN-DNA frame, determine whether the frame is well-formed
> and cryptographically valid under the public epoch key material supplied to
> the verifier, then emit deterministic evidence for that decision.

The verifier is designed to answer:

- Was this frame structurally valid?
- Did the signature verify under the supplied epoch public key?
- Did the frame satisfy the enforced verifier directives?
- Was the decision reproducible?
- Was the audit chain preserved without tampering, reordering, duplication, or
  deletion?

The verifier is **not** designed to answer:

- Was the physical device uncompromised?
- Was the signer authorized by organizational policy?
- Was the user's intent benign?
- Was the prover-side D0 derivation secure?
- Was the device's genesis polynomial protected?
- Did key operations occur inside trusted hardware?

---

## 4. Assets

### 4.1 Cryptographic and Verification Assets

- `mu_pre`
- `T_E`
- ML-DSA-44 public key material
- ML-DSA-44 signature
- frame digest
- verification decision
- error code
- contract version
- schema version

### 4.2 Evidence Assets

- `verification_log.json`
- `andna_audit.jsonl`
- `audit_validate.json`
- `evidence.json`
- `manifest.json`
- `verification_digest`
- audit-chain `record_hash`
- audit-chain `prev_hash`

### 4.3 Build and Integrity Assets

- `libandna_ffi.so`
- `libandna_ffi.integrity`
- `ANDNA-INTEGRITY-v1` reference file
- Gate 1 artifact-bundle hashes
- Docker build configuration
- HostB proof workflow
- pinned Rust toolchain
- pinned Docker base image
- pinned liboqs build configuration

---

## 5. Trust Assumptions

The verifier relies on the following assumptions.

### 5.1 Public-Key Authenticity Assumption

The verifier assumes that the epoch public key material supplied in or through
`T_E` is the intended public key for the claimed verification context. The
verifier can check whether a signature is valid under a public key. It cannot
independently prove that the public key was legitimately derived by a specific
device unless that claim is supplied and validated by an external registry,
hardware attestation system, or prover-side protocol.

### 5.2 Prover Secret Custody Assumption

The verifier assumes that prover-side secrets, including any genesis polynomial
or device identity secret, are generated and protected outside the verifier
boundary. If a prover-side genesis polynomial or equivalent root secret is
compromised, an attacker may be able to produce valid epoch keys and valid
signatures. The verifier cannot distinguish those signatures from signatures
produced by the legitimate device.

### 5.3 Hardware Root-of-Trust Assumption

The verifier does not currently verify hardware attestation. Any claim that key
operations occurred inside TPM 2.0, TrustZone, a secure element, or another
hardware-protected environment is outside the verifier boundary unless
integrated through a future attestation mechanism.

### 5.4 Deployment Integrity Assumption

For Path A′ software integrity, the verifier relies on trusted deployment
configuration for:

- `ANDNA_INTEGRITY_MODULE_PATH`
- `ANDNA_INTEGRITY_REF_PATH`

These paths identify the module artifact and associated integrity reference
file. If an attacker controls both the module path and reference path, the
verifier's software-integrity check can be redirected to attacker-controlled
artifacts. Therefore, the Path A′ integrity mechanism detects artifact mismatch
under the approved build and deployment process. It is not claimed to prevent
forgery by a fully privileged attacker who controls the runtime environment and
can replace both the module and the reference file.

### 5.5 Runtime Environment Assumption

The verifier assumes the runtime environment can load the intended library,
read the intended integrity reference, and execute the verifier without
malicious interference from the operating system or loader. A fully compromised
host can interfere with verifier execution, alter process memory, redirect file
paths, suppress logs, or replace artifacts. Such a host is outside the
verifier's defended boundary.

---

## 6. Adversary Classes

### A1 — Malformed Input Attacker

Capabilities:

- Provides malformed frames.
- Provides frames with incorrect lengths.
- Mutates `mu_pre`, `T_E`, or signature fields.
- Attempts to trigger parser or boundary errors.

Defenses:

- Strict frame length checks.
- Null pointer checks at the FFI boundary.
- Directive checks before cryptographic acceptance.
- Structured error codes.
- Panic containment at the FFI boundary.

Expected outcome:

- Malformed or invalid inputs are rejected.
- The verifier does not enter an undefined success state.

---

### A2 — Signature Forgery Attacker

Capabilities:

- Attempts to create a valid frame without the corresponding ML-DSA-44 private
  key.
- Attempts to mutate the message or signature while preserving acceptance.

Defenses:

- ML-DSA-44 verification through the Rust/liboqs path.
- ACVP-derived ML-DSA-44 KAT coverage.
- Signature-invalid rejection path.
- Public-key hash binding checks.

Expected outcome:

- Frames without valid ML-DSA-44 signatures are rejected.

Limit:

- The verifier does not prove that the private key was generated honestly or
  protected by hardware. It only verifies possession of the corresponding
  signing key at signing time.

---

### A3 — Frame-Tampering Attacker

Capabilities:

- Modifies frame bytes after generation.
- Flips bytes in the frame.
- Attempts to alter public key material, epoch material, device ID material, or
  signature material.

Defenses:

- Frame digest calculation.
- Public-key hash binding.
- Device ID derivation check.
- Epoch correlation check.
- Signature verification.
- Deterministic evidence logging.

Expected outcome:

- Tampered frames are rejected.
- The rejection is logged with deterministic evidence fields.

---

### A4 — Replay / Evidence Consistency Attacker

Capabilities:

- Replays prior logs.
- Attempts to alter recorded decisions.
- Attempts to create inconsistency between recorded and recomputed decisions.

Defenses:

- Deterministic replay.
- Verification digest over deterministic decision fields.
- Replay check comparing recorded decision with re-verification result.
- Audit evidence export.

Expected outcome:

- The same frame under the same contract path yields the same deterministic
  decision.
- Replay detects disagreement between recorded and recomputed decision
  behavior.

Limit:

- The verifier does not, by itself, decide whether a previously valid frame
  should remain authorized under future policy or revocation state. See
  Section 6.5.

---

### A5 — Audit-Chain Tampering Attacker

Capabilities:

- Modifies audit log records.
- Reorders records.
- Duplicates records.
- Deletes records.
- Attempts to preserve superficial evidence output while corrupting the
  authoritative chain.

Defenses:

- Append-only audit-chain structure.
- 0-based sequence enforcement.
- `prev_hash` linkage.
- `record_hash` validation.
- Gate 2 T1/T2/T3 acceptance harness:
  - T1 baseline,
  - T2 tamper-evidence,
  - T3.1 reorder detection,
  - T3.2 duplication detection,
  - T3.3 deletion detection.

Expected outcome:

- Tampered, reordered, duplicated, or deleted audit chains fail validation.

Note:

- This is a local tamper-evident audit chain. It borrows the hash-linked logic
  of tamper-evident logs but is not a public transparency log: there is no
  public append-only log infrastructure, no Merkle consistency proofs, and no
  external monitor/gossip layer. It is local evidence, validated locally.

---

### A6 — Build Drift / Reproducibility Attacker

Capabilities:

- Attempts to introduce untracked source drift.
- Exploits platform line-ending differences.
- Exploits unpinned toolchains or host-specific build behavior.
- Produces artifacts that differ from the expected proof lane.

Defenses:

- Pinned Docker base image.
- Pinned Rust toolchain.
- Pinned liboqs build lane.
- Deterministic C/C++ build flags.
- LF line-ending policy.
- Docker/HostB proof lane.
- Gate 1 artifact-bundle hashes.

Expected outcome:

- The approved proof lane produces reproducible artifact-bundle hashes across
  local Docker and HostB.

Limit:

- Reproducibility is claimed for the pinned proof lane, not for arbitrary host
  builds or unpinned local development environments.

---

### A7 — Module Artifact Replacement

Capabilities:

- Replaces `libandna_ffi.so`.
- Replaces `libandna_ffi.integrity`.
- Attempts to run a mismatched module/reference pair.

Defenses:

- Path A′ HMAC-SHA-256 software integrity check.
- `ANDNA-INTEGRITY-v1` reference file.
- Artifact SHA-256 check.
- HMAC-SHA-256 over the full module artifact.
- Constant-time tag comparison.
- Fail-closed behavior when:
  - env paths are missing,
  - reference parsing fails,
  - artifact SHA-256 mismatches,
  - HMAC tag mismatches,
  - module or reference file is missing.

Expected outcome:

- A mismatched module/reference pair fails closed.
- A tampered module fails against its original reference.
- A tampered reference fails against its original module.

Limit:

- If an attacker controls both the module and the associated reference file,
  and also controls the trusted deployment configuration paths, the verifier
  cannot distinguish an attacker-generated matching pair from an approved
  matching pair. This is a deployment integrity and trust-boundary issue, not a
  cryptographic failure of the HMAC calculation. The embedded HMAC key is
  non-secret by design (see Section 7.2).

---

### A8 — Compromised Prover Hardware

Capabilities:

- Extracts or controls a prover-side genesis polynomial or equivalent device
  root secret.
- Derives legitimate epoch keys.
- Produces valid signatures for malicious activity.
- Mimics normal signing cadence.

Defenses inside verifier:

- **None that can distinguish this case from legitimate signing.**

Expected outcome:

- If the attacker can produce valid epoch private keys and valid signatures,
  the verifier will accept structurally valid frames.

Reason:

- A valid signature proves possession of the signing key at signing time. It
  does not prove that the signing key was used by uncompromised hardware or by
  an authorized actor. This is a key-provenance boundary, not a verifier
  vulnerability: the verifier is designed to be blind to prover-side state.

Mitigation outside verifier:

- Hardware attestation.
- Secure element / TPM / TrustZone custody.
- Device registry controls.
- Revocation workflows.
- Epoch-velocity anomaly detection at the registry/application layer. Note that
  velocity detection catches abnormal epoch advancement (a "greedy" attacker
  minting epochs faster than the legitimate schedule) but does **not** detect a
  patient attacker who mimics the legitimate device's signing cadence. No
  registry-side heuristic detects a quiet, cadence-matching compromise; only
  hardware attestation addresses that case.

Status:

- Out of scope for the R1 verifier boundary.
- Must be addressed by prover-side and deployment architecture.

---

### 6.5 Application-Layer Epoch and Revocation Model

The R1 verifier does not perform revocation, epoch-rollover authorization, or
registry-freshness checks. These are intentionally handled by a separate
application-layer registry/policy gate, outside the verifier boundary.

This separation preserves verifier determinism. The verifier emits only the
cryptographic decision and the deterministic `verification_digest`. A
deployment combines that decision with a signed registry snapshot to produce a
separate policy decision and `policy_digest`.

Two-stage decision model:

- **Stage 1 — Cryptographic verifier (R1, in scope).**
  Input: frame. Output: ACCEPT / REJECT. Anchored by `verification_digest` over
  (`frame_hash`, `frame_len`, `decision`, `error_code`, `contract_version`).

- **Stage 2 — Registry / policy gate (out of scope for R1).**
  Input: the Stage 1 decision plus a signed registry snapshot. Output:
  AUTHORIZED / NOT AUTHORIZED. Anchored by a separate `policy_digest`.

Final outcomes:

- `CRYPTO_REJECT` → final reject, regardless of policy.
- `CRYPTO_ACCEPT` + `POLICY_REVOKED` → final reject.
- `CRYPTO_ACCEPT` + `POLICY_ACTIVE` → final accept.

The `verification_digest` is deliberately **not** contaminated with revocation
or epoch-window state. Its value is precisely that the same frame yields the
same cryptographic result across hosts and over time. Revocation,
epoch-rollover grace windows, and device-status policy evolve in the registry
layer without altering verifier semantics.

Epoch rollover (registry-driven, illustrative): current epoch accepted;
previous epoch accepted only within a grace window; future epoch rejected
unless pre-authorized; multiple active `T_E` for one device/epoch treated as a
registry conflict.

Revocation (registry-driven): by device, by epoch, by `T_E` hash, or by
suspected genesis/root compromise.

This model is described here to make the verifier's boundary explicit. The
registry/policy layer, its signed-snapshot format, and its freshness guarantees
are R2 design work and are **not implemented in R1**.

---

## 7. Software Integrity Model

AN-DNA R1 currently implements Path A′ software integrity.

### 7.1 Path A′ Definition

The module integrity bundle consists of:

- `libandna_ffi.so`
- `libandna_ffi.integrity`

The integrity reference uses the `ANDNA-INTEGRITY-v1` format and includes:

- artifact name,
- algorithm identifier,
- key ID,
- key status,
- HMAC-SHA-256 tag,
- artifact SHA-256 digest.

At power-up, the FFI module:

1. Runs HMAC-SHA-256 CAST.
2. Runs SHAKE256 KAT.
3. Runs ML-DSA-44 KAT.
4. Reads the configured module artifact path.
5. Reads the configured integrity reference path.
6. Parses the reference.
7. Computes SHA-256 over the module artifact.
8. Computes HMAC-SHA-256 over the module artifact.
9. Compares the computed values to the reference.
10. Enters Approved state only if all checks pass.

### 7.2 HMAC Key Status

The HMAC key is non-secret and used only for software-integrity self-test. No
claim is made that the key is confidential or protected from a fully privileged
adversary. The mechanism is intended to detect artifact mismatch in the
approved build/deployment process, not to provide unforgeability against an
attacker who can replace both the module and reference file.

This is artifact-bundle integrity under a controlled deployment process. It is
deliberately not labeled anti-tamper protection, because a privileged attacker
who can modify `libandna_ffi.so` can also read the non-secret key, recompute
the HMAC tag, and rewrite the reference file.

### 7.3 Deployment Boundary

The environment variables:

- `ANDNA_INTEGRITY_MODULE_PATH`
- `ANDNA_INTEGRITY_REF_PATH`

are part of trusted deployment configuration. Incorrect or malicious
configuration can cause the verifier to check unintended artifacts. Production
deployments must control these paths through deployment policy, file
permissions, container configuration, or equivalent mechanisms.

---

## 8. Self-Test Model

The FFI module uses a power-up self-test sequence before entering Approved
state.

Current sequence:

1. HMAC-SHA-256 CAST.
2. SHAKE256 KAT.
3. ML-DSA-44 ACVP-derived KAT.
4. Path A′ software-integrity check.

If any test fails, the module enters an error state and does not enter Approved
state.

The development-only `fips-integrity-stub` feature remains available for local
non-FIPS workflows, but it is non-conformant and is not the authoritative
software-integrity lane. The authoritative Docker/HostB proof lane uses
`fips-integrity-hmac`. A crate-root `compile_error!` enforces that exactly one
of the two integrity modes is selected.

---

## 9. Gate 1 and Gate 2 Evidence

### 9.1 Gate 1 — Artifact-Bundle Reproducibility

Gate 1 records artifact-bundle hashes for:

- `target/release/libandna_ffi.so`
- `target/release/libandna_ffi.integrity`

Gate 1 is no longer a single binary-only hash. Under Path A′, the integrity
reference is part of the verifier artifact bundle. See `fips/gate1_golden.md`.

### 9.2 Gate 2 — Deterministic Verification Evidence

Gate 2 validates deterministic verification behavior and audit-chain integrity.
The `verification_digest` covers deterministic verification fields only:

- frame hash,
- frame length,
- decision,
- error code,
- contract version.

It excludes timestamps, run IDs, and engine names.

The Gate 2 verification digest is independent of the HMAC software-integrity
reference mechanism. HMAC changes the module artifact bundle; it does not change
deterministic frame verification semantics.

---

## 10. Residual Risks

### R1 — Prover Compromise

The verifier cannot detect compromise of prover-side root secrets or hardware.
If an attacker can produce valid epoch private keys and valid signatures, the
verifier cannot distinguish the attacker from the legitimate device. Mitigation
requires hardware custody, attestation, registry policy, revocation, or
prover-side redesign.

### R2 — D0 Bridge Unreviewed

The D0 epoch-witness bridge is outside the verifier codebase and requires
independent cryptographic review before production security claims are made
about forward-epoch isolation or prover-side derivation.

### R3 — Fully Compromised Host

A fully compromised host can replace binaries, redirect environment variables,
tamper with process memory, suppress logs, or bypass execution. The verifier
does not defend against a fully compromised operating system.

### R4 — Deployment Configuration Control

Path A′ depends on trusted configuration of module and reference paths.
Misconfiguration can invalidate the intended integrity check.

### R5 — Validation Status

The project is not FIPS 140-3 validated. The current implementation is a
pre-validation engineering artifact with an explicit validation roadmap.
Implementing CAST and KAT patterns does not, by itself, constitute or
approximate FIPS 140-3 validation, which is established through the CMVP process
and an accredited CST laboratory, not by self-assertion.

### R6 — Bus Factor and Review

The implementation has not yet received independent external cryptographic or
security review. Design-partner and expert review are required before
production deployment claims are made.

---

## 11. Explicit Non-Claims

AN-DNA R1 does not currently claim:

- FIPS 140-3 validation.
- ACVP/CAVP certificate issuance.
- Formal security proof for the D0 bridge.
- Detection of compromised prover hardware.
- Detection of malicious user intent.
- Behavioral legitimacy analysis.
- Protection against a fully compromised host.
- HMAC key secrecy.
- Tamper-proof execution.
- Unforgeability of the integrity bundle against an attacker who controls both
  module and reference file.
- Replacement of SIEM, TEE, TPM, secure enclave, or zkVM systems.

---

## 12. Future Work

Future work is tracked separately from the R1 verifier boundary. Priority items:

1. Independent review of the D0 epoch-witness bridge.
2. Formalization of prover-side assumptions and security argument.
3. Hardware-attestation integration design.
4. Registry-layer epoch-velocity and revocation policy (Stage 2 of the
   two-stage model in Section 6.5).
5. Production deployment profile for Path A′ integrity configuration.
6. Possible Path B sealed-binary integrity packaging.
7. External security/code review of the FFI boundary and proof lane.
8. Formal validation planning if FIPS 140-3 becomes a business-critical path.

---

## 13. Summary

AN-DNA R1 is a verifier-side trust artifact. It verifies structured
post-quantum authentication frames, emits deterministic evidence, validates
audit-chain integrity, and performs HMAC-SHA-256 software integrity checking
over the module artifact using an associated `ANDNA-INTEGRITY-v1` reference
file.

The verifier is intentionally blind to prover secrets and hardware state. That
public-verifier design reduces shared-secret exposure, but it also means the
verifier cannot detect compromised prover hardware or validate prover-side D0
security claims.

The correct security posture is:

> AN-DNA R1 provides deterministic, replayable, and tamper-evident verification
> evidence for public-key authentication frames inside a pinned proof lane.
> Prover-side identity derivation, hardware custody, and D0 bridge security are
> outside the R1 verifier boundary and require separate review and integration.

---

## 14. Revision History

| Version | Date | Change |
|---|---|---|
| 1.0.0 | 2026-05-30 | Initial verifier-only threat model. Scope A (verifier boundary). Adversary classes A1–A8 with defenses mapped to shipped code; A8 (compromised prover hardware) documented as undefended at the verifier with the velocity-detection caveat. Added Section 6.5 (two-stage application-layer epoch/revocation model). Trust assumptions, residual risks, and explicit non-claims aligned with the FIPS package non-claims (non-secret HMAC key, env-var trust boundary, pre-validation status). |