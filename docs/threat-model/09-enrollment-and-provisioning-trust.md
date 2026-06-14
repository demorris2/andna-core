# 09 — Enrollment and Provisioning Trust

## Why this document exists

Every R2 authorization decision assumes that the registry was populated with *legitimate*
`te_hash` entries — entries that genuinely correspond to devices whose operators intended to
authorize them. If this assumption is violated at enrollment time, R2 will authorize an
adversarial device with the same confidence it would authorize a legitimate one.

This is the **GIVDO problem at provisioning time**: an attacker who can insert their own
keypair into the registry during enrollment achieves "authentic" status — R1 will verify
their frames, R2 will authorize them — without ever having a legitimate identity.

Neither prior security reviews nor the current threat model addressed enrollment explicitly.
This document fills that gap.

## Built / true today

Enrollment is currently **out-of-band and operator-asserted**:

1. The sealer runs `init-sealer` (or `SoftwareProfileSigner::from_seed`) to generate a
   local software profile containing seed material and device identity.
2. The sealer's `te_hash` (the SHA3-256 of the initial epoch public key T_E) is written
   into the local registry JSON by the operator.
3. No third party verifies that the `te_hash` in the registry corresponds to a legitimate
   device. The operator is the sole authority.

In the demo/MVP, the sealer writes its own registry entry. This is the self-authorization
model: the device asserted itself into its own registry.

## Threat analysis

### Rogue enrollment

An attacker generates their own keypair and submits the resulting `te_hash` to the operator
for inclusion in the registry. If the operator accepts it without verifying key origin, the
attacker holds a fully authorized identity. R1 and R2 will both process the attacker's
frames correctly.

**Current mitigation:** none at the cryptographic layer. The operator's out-of-band vetting
process is the only control. For demo/MVP, the operator is also the sealer, so this is a
degenerate case.

### Enrollment-time key substitution

An adversary intercepts the enrollment channel (e.g. a registry submission API, a manual
copy step, a configuration management pipeline) and replaces a legitimate `te_hash` with
their own. The legitimate device's `te_hash` is never added; the attacker's is.

**Current mitigation:** none. The registry JSON is an unprotected file; substitution during
transit or at the destination is undetectable without a separate integrity check on the
registry itself.

### Registry seeding without provenance

The initial registry is created by the operator with no cryptographic proof that entries
came from the stated devices. An operator who is compromised, coerced, or mistaken can
populate the registry with illegitimate entries.

**Current mitigation:** the `snapshot_hash` in evidence binds the specific registry used for
each decision. An auditor can verify that a specific decision was made against a specific
registry state. This does not prevent the registry from having been populated incorrectly.

### Unauthenticated `te_hash` submission

If a future version adds an enrollment API (e.g. a device self-registers by posting its
`te_hash`), that API must be authenticated and authorized before the `te_hash` is added.
Unauthenticated self-registration is equivalent to rogue enrollment.

## Not yet built (future mitigations)

- **Attested enrollment**: a device presents a hardware attestation (TPM quote, SE certificate,
  SGX report) alongside its `te_hash` at enrollment time; the registry authority verifies
  the attestation before adding the entry.
- **Provenance-signed registry entries**: each registry entry carries a signature from the
  enrollment authority, proving which authority vouched for the device at enrollment time.
- **Enrollment ceremony with witness**: a multi-party enrollment protocol where at least two
  parties (the device, a human operator, and/or an enrollment witness) must agree before a
  `te_hash` is added to the registry.
- **Hardware-attested key origin**: the device's keypair is generated inside a hardware
  security boundary (TPM, SE, SGX); the enrollment authority receives a hardware attestation
  proving the private key cannot be extracted.

## Reviewer questions

1. For the current pilot scope (operator is also the sealer), is the out-of-band self-
   authorization model explicitly acceptable, or does it need a process control (e.g. a
   second operator must approve each registry entry)?
2. Should the threat model require a minimum enrollment ceremony (e.g. at least one human
   review step per `te_hash` addition) before any production deployment, regardless of
   hardware attestation availability?
3. Is "GIVDO problem at provisioning time" the right framing for reviewers who may not be
   familiar with that threat model terminology?
