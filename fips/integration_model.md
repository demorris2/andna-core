# AN-DNA Integration Model — Trust Composition

**Document status:** Draft
**Version:** 1.0.2
**Date:** 2026-05-30
**Maintainer:** Darrell Morris Jr. — ArcNeura
**Scope:** How the AN-DNA R1 verifier composes with hardware roots of trust
and a registry/policy layer to address trust concerns that are out of scope
for the verifier itself
**Relationship to other documents:** This document is the companion to
`fips/threat_model.md`. The threat model defines what the R1 verifier defends,
assumes, and cannot know. This document defines how the verifier's
out-of-scope assumptions are intended to be discharged in a production
deployment through standards-based composition.

---

## 0. Reading This Document — Status Labels

Every section in this document is labeled with one of three status markers, so
that a reader can distinguish what exists from what is planned:

- **[IMPLEMENTED — R1]** — exists in the shipped `andna-core` codebase and is
  covered by the threat model.
- **[ARCHITECTURE — COMMITTED]** — a design decision ArcNeura commits to. The
  interface and the composition pattern are settled; the implementation is R2
  work. These are not exploratory; they are the intended architecture.
- **[SPECIFIED — R2, NOT IMPLEMENTED]** — described here at the level needed to
  evaluate the composition, but deliberately not yet pinned to a specific
  vendor, version, or substrate. Open design space.

No section of this document describes a deployed or validated production
system. AN-DNA R1 is a verifier; the registry, policy gate, and
hardware-attestation integration described here are R2 design work.

---

## 1. Purpose and Position

### 1.1 The composition problem [IMPLEMENTED — R1 context]

The AN-DNA R1 verifier answers one question with cryptographic precision: given
a frame and public epoch key material, did the holder of the corresponding
private key produce a valid signature over a canonically-constructed payload?

The threat model is explicit about what that question does **not** answer
(Adversary Class A8, Residual Risks R1 and R2): the verifier cannot determine
whether the signing key was generated and used inside trusted hardware, whether
the device is currently authorized, or whether the prover-side derivation that
produced the key was secure. A valid signature proves key possession at signing
time and nothing more.

These are not defects to be patched inside the verifier. They are the
consequence of a deliberate public-verifier design that holds no secrets and
maintains no state. The correct response is not to expand the verifier — which
would compromise the determinism and minimal trust surface that make it
valuable — but to **compose** it with other components that answer the
adjacent questions.

### 1.2 AN-DNA as a trust component, not a trust system [ARCHITECTURE — COMMITTED]

ArcNeura's position is that AN-DNA is a **trust component**: it does one narrow
thing well and integrates with the rest of a modern device-trust stack rather
than attempting to replace it. The verifier is one element alongside a hardware
root of trust, an attestation-verification step, a device registry, and a
policy gate. The security property a deployment actually wants emerges from the
composition, not from any single element.

Two questions, composed:

- AN-DNA (cryptographic): "The holder of the right private key signed this
  frame."
- Hardware attestation (provenance): "And that key was generated and is held
  inside a genuine, hardware-protected device — not extracted material on an
  attacker's machine."

Their conjunction — "a real, hardware-protected device signed this frame" — is
the production property. Neither component provides it alone.

### 1.3 What this document does not do

This document does not invent cryptography or attestation protocols. The
device-attestation problem has been worked on by the broader community for over
a decade, and the composition described here consumes that work (Section 4). It
also does not specify the AN-DNA prover side or the D0 epoch-witness bridge;
those are described in the companion protocol document and require independent
review (threat model R2). This document is concerned only with how the verifier
composes outward.

---

## 2. The Two-Stage Decision Model (Recap and Extension)

### 2.1 Recap from the threat model [IMPLEMENTED — R1 interface]

The threat model Section 6.5 defines a two-stage decision model. This document
extends Stage 2; the stages are restated here for self-containment.

- **Stage 1 — Cryptographic verifier (R1, in scope).**
  Input: frame. Output: ACCEPT / REJECT. Anchored by `verification_digest`
  over (`frame_hash`, `frame_len`, `decision`, `error_code`,
  `contract_version`). Deterministic, stateless, holds no secrets. This is the
  shipped verifier.

- **Stage 2 — Registry / policy gate (out of scope for R1).**
  Input: the Stage 1 decision plus a signed registry snapshot. Output:
  AUTHORIZED / NOT AUTHORIZED. Anchored by a separate `policy_digest`. This is
  the layer this document specifies.

Final outcomes are unchanged: `CRYPTO_REJECT` is a final reject regardless of
policy; `CRYPTO_ACCEPT` + `POLICY_REVOKED` is a final reject; `CRYPTO_ACCEPT` +
`POLICY_ACTIVE` is a final accept.

Composition at a glance:

```
Frame
  │
  ▼
Stage 1 — AN-DNA R1 verifier  [IMPLEMENTED — R1]
  → CRYPTO_ACCEPT / CRYPTO_REJECT
  → verification_digest   (purely cryptographic, deterministic)
  │
  ▼  (only if CRYPTO_ACCEPT)
Stage 2 — Registry / policy gate  [SPECIFIED — R2]
  inputs:  verification_digest
           signed registry snapshot (device status, epoch policy, T_E_hash)
           attestation status
  → AUTHORIZED / NOT AUTHORIZED + typed reason code
  → policy_digest         (time-varying state allowed here)
  │
  ▼
Final decision:
  CRYPTO_REJECT                        → reject
  CRYPTO_ACCEPT + AUTHORIZED           → accept
  CRYPTO_ACCEPT + NOT AUTHORIZED       → reject
```

If Stage 1 returns `CRYPTO_REJECT`, Stage 2 is not evaluated: `policy_digest` is
null or absent, and the final decision is anchored solely by
`verification_digest`. Stage 2 evidence exists only for frames that passed
cryptographic verification.

### 2.2 Why the digests stay separate [ARCHITECTURE — COMMITTED]

The `verification_digest` is never contaminated with attestation state,
revocation state, or any time-varying policy input. Its value is precisely that
the same frame yields the same cryptographic result across hosts and over time.
Attestation freshness, revocation status, and epoch-rollover windows are all
time-varying; binding them into the cryptographic digest would destroy its
reproducibility. They belong in the `policy_digest`, which is allowed to depend
on the registry snapshot at decision time.

This separation is the single most important architectural invariant in the
composition. It is committed and non-negotiable: hardware attestation,
registry, and policy logic compose *around* the verifier, never *inside* it.

### 2.3 The policy_digest [ARCHITECTURE — COMMITTED concept, recipe SPECIFIED]

Stage 2 needs the same evidentiary discipline R1 has. Just as the
`verification_digest` anchors the cryptographic decision, the `policy_digest`
anchors the policy decision so that a Stage 2 outcome is itself auditable and
reproducible against a known registry snapshot.

Illustrative recipe (fields may be refined in R2):

```
policy_digest = SHA3-256(canonical_policy_record)

canonical_policy_record = {
  stage1_verification_digest   # binds the policy decision to the exact crypto result
  frame_hash
  device_id32
  epoch
  T_E_hash
  registry_snapshot_hash       # identifies the signed registry state consulted
  registry_sequence            # snapshot freshness
  registry_issuer_id           # identifies the signer of the snapshot
  registry_signature_hash      # the specific signature instance over the snapshot
  policy_version
  policy_decision              # AUTHORIZED / NOT AUTHORIZED
  policy_reason_code           # typed reason (Section 5.5)
  decision_time
}
```

Together, `registry_snapshot_hash` (content), `registry_issuer_id` (signer), and
`registry_signature_hash` (signature instance) identify *what* state was
consulted, *who* signed it, and *which* signature was verified — sufficient to
reconstruct and audit the policy decision.

The committed part is that a `policy_digest` exists, is distinct from
`verification_digest`, and binds the policy decision to (a) the cryptographic
result it followed and (b) the specific signed registry snapshot it consulted.
The exact field set is R2 design work. **R2 must also define a canonical
serialization for `canonical_policy_record`**: field ordering, encoding (e.g.
deterministic CBOR, canonical JSON, or a fixed binary layout), timestamp
representation, integer widths, and hash algorithms must be locked before
`policy_digest` is treated as reproducible evidence — the same discipline that
makes the R1 `verification_digest` reproducible across hosts.

---

## 3. Hardware-Attested Device Enrollment

This is the primary mechanism for addressing the compromised-hardware gap
(threat model A8 / R1).

### 3.1 The enrollment-time attestation pattern [ARCHITECTURE — COMMITTED]

When a device enrolls in the registry, it performs a hardware-attested key
generation. The device's root key material — the genesis polynomial or the root
from which epoch keys are derived — is generated inside a hardware-protected
environment (a TPM 2.0, an ARM TrustZone TEE, a secure element, or a cloud TEE;
see Section 4). The device produces an **attestation quote**: evidence, signed
by a manufacturer-rooted attestation key, that the key was generated under an
approved hardware-backed policy and bound to an attested hardware instance at
enrollment time.

This evidence establishes provenance *at enrollment*. It does not by itself
prove the key *continuously* resides in protected hardware and is never
extracted afterward; that stronger property depends on key non-exportability
attributes, the attestation policy, implementation correctness, and the trust
root, and is fully obtained only under per-operation attestation (Section 3.3)
or hardware-backed signing (Section 3.4).

The registry verifies that attestation quote **once, at enrollment**, against
the appropriate hardware trust roots, and records a binding:

```
device_id32  ⟷  attested hardware instance
```

After enrollment, the AN-DNA verifier runs unchanged. It never sees the
attestation; the attestation is a registry-layer (Stage 2) concern.

### 3.2 What this buys, precisely [ARCHITECTURE — COMMITTED]

This pattern does not make the A8 quiet-compromise case fully detectable — the
threat model is honest that no registry heuristic detects a patient attacker who
both holds extracted key material and mimics legitimate signing cadence. What
enrollment-time attestation changes is the **enrollment surface**:

- An attacker who exfiltrates a genesis polynomial can produce valid signatures
  for the *already-enrolled* device, but cannot **enroll a new device** — they
  lack the hardware to produce a fresh, valid attestation quote.
- If the legitimate device is in the registry, its compromise can be acted on
  through revocation (Section 5), bounding the damage window once compromise is
  suspected.

This is a meaningful reduction of the A8 attack surface (new-device forgery is
closed; existing-device compromise is bounded by revocation), stated without
overclaiming that it closes A8 entirely. Full closure of the quiet-compromise
case requires hardware-backed signing (Section 3.4), not merely enrollment-time
attestation.

### 3.3 Per-operation attestation [SPECIFIED — R2, NOT IMPLEMENTED]

For high-value operations (administrative actions, key recovery, financial
authorization), a deployment may require an attestation quote with *every*
signature, proving the signing key is *currently* inside protected hardware at
the moment of use. This catches extraction attacks even after enrollment: an
attacker with extracted key material cannot produce fresh per-operation quotes.

The cost is per-signature attestation overhead (latency, bandwidth, complexity),
which is why this is appropriate for a subset of operations rather than the
default path. The composition is identical to enrollment-time attestation: the
quote travels alongside the frame and is evaluated in Stage 2, never inside the
verifier frame format.

### 3.4 Hardware-backed signing [SPECIFIED — R2, NOT IMPLEMENTED]

The strongest property is achieved when the signing operation itself executes
inside the protected hardware: the root key never leaves the secure element, and
ML-DSA-44 signing runs in the TEE. Possession of a valid key then cryptographically
implies possession of working trusted hardware, which is the property that fully
addresses the A8 quiet-compromise case.

This property holds only under specific conditions, which a deployment must
verify rather than assume: the signing key must be generated as non-exportable,
the signing path must be covered by the attested measurement or hardware policy,
the hardware root of trust must remain trusted (not revoked or compromised), and
the hardware policy must be correctly implemented. Absent any of these, the
"valid key implies trusted hardware" implication weakens.

This is deliberately marked not-implemented and is the furthest-out item.
Constraints, stated honestly:

- ML-DSA-44 support in commodity secure elements and TPMs is new and not yet
  widely available.
- ML-DSA-44 has larger memory and key-size requirements than RSA/ECDSA, which is
  tight inside constrained TEEs.
- A deployment depending on hardware-backed PQ signing is at the mercy of the
  hardware ecosystem's maturity.

The standards picture is moving quickly, and the honest framing distinguishes
the *specification* from *deployed availability*. The TCG TPM 2.0 Library
Specification v1.85 (2026) adds ML-DSA (including attestation-key use) and
ML-KEM (including endorsement-key use), with new sequence-based signing commands
(SignVerifySequenceStart / SignSequenceComplete / VerifySequenceComplete) that
handle ML-DSA's large messages within TPM memory constraints. Early software and
firmware-TPM support exists (e.g. wolfTPM implementing the v1.85 PQC commands on
top of FIPS 203/204 modules). However, commodity *deployed* hardware — the
installed base of discrete TPMs, secure elements, and production device fleets —
should not be assumed to support ML-DSA-44 signing today; adoption in shipping
silicon and certified modules lags the specification. ArcNeura therefore tracks
hardware-backed PQ signing as future-facing: the near-term high-assurance path is
enrollment-time attestation (Section 3.1) plus the registry/policy gate, not
per-operation hardware-backed ML-DSA signing.

### 3.5 Registry object shape [SPECIFIED — R2, NOT IMPLEMENTED]

Illustrative, not final. The registry device-status object would carry the
fields needed for both policy (Section 5) and attestation:

```
device_id32          # bound identity
epoch                # current registered epoch
T_E_hash             # registered epoch public key hash
status               # active | revoked | expired | superseded
valid_from
valid_until
registry_sequence    # monotonic, for snapshot freshness
attestation_evidence # enrollment-time quote (or reference to it)
attestation_format   # which standard the quote conforms to (Section 4)
attestation_roots    # which trust roots validated the quote
policy_version
issuer_signature     # registry's signature over the snapshot
```

The exact schema, serialization, and signing scheme are R2 design work. What is
committed is that the registry snapshot is itself signed and freshness-bounded
(via `registry_sequence`), so that Stage 2 can detect a stale or forged snapshot.

---

## 4. Attestation Standards (Consumption, Not Invention)

### 4.1 Primary integration target: IETF RATS / EAT [ARCHITECTURE — COMMITTED]

The composition consumes standards-based remote attestation. The primary
integration target is the IETF Remote ATtestation procedureS (RATS)
architecture (RFC 9334) and the Entity Attestation Token (EAT) format. RATS is
the modern, vendor-neutral framework for conveying and appraising attestation
evidence, and EAT is its claims-token format. Targeting RATS/EAT as the
appraisal interface lets the registry accept evidence from heterogeneous
underlying hardware without a bespoke integration per vendor.

### 4.2 Consumable underlying formats [ARCHITECTURE — COMMITTED, instances SPECIFIED]

Underneath the RATS/EAT appraisal interface, the registry would consume
attestation evidence in the formats native to the deployment's hardware:

- **W3C WebAuthn (Level 3) attestation** — battle-tested device-enrollment
  attestation, in production at scale; appropriate for client-device fleets.
- **TCG Remote Attestation / TPM 2.0 quotes** — server and datacenter
  ecosystems; appropriate for traditional infrastructure.
- **ARM PSA Attestation Token (PSA-AT)** — ARM ecosystems; appropriate for
  IoT and edge.
- **Cloud TEE attestation documents** — e.g. AWS Nitro attestation, Google
  Confidential VM, Azure Attestation; appropriate for TEE-based cloud
  deployments.
- **Mobile attestation** — Android Key Attestation, iOS App Attest /
  DeviceCheck; appropriate for mobile fleets.

The commitment is to consume standards-based attestation through the RATS/EAT
appraisal interface. Which specific underlying formats a given deployment
supports is a deployment choice, marked specified rather than committed because
ArcNeura does not pre-select the customer's hardware.

### 4.3 Why consume rather than invent [ARCHITECTURE — COMMITTED]

Building a new attestation framework on top of AN-DNA would be a serious
mistake. The community has spent more than a decade getting remote attestation
right — evidence formats, freshness, trust-root management, appraisal policy.
The composition consumes that work. AN-DNA contributes the deterministic
post-quantum verification; it does not re-derive attestation.

---

## 5. Registry, Revocation, and Epoch Rollover

### 5.1 Revocation [SPECIFIED — R2, NOT IMPLEMENTED]

Revocation is registry-driven and evaluated in Stage 2. A device, an epoch, or a
specific `T_E_hash` can be revoked; a suspected genesis/root compromise revokes
at the device level. The policy gate consults the (signed, freshness-bounded)
registry snapshot and returns `POLICY_REVOKED` for any frame whose
device/epoch/key is on the deny set, overriding a Stage 1 `CRYPTO_ACCEPT`.

Implementation mechanics (deny-list representation, distribution to distributed
verifiers, synchronization protocol, freshness guarantees) are R2 design work.
What is committed is the *placement*: revocation lives in Stage 2 and never
alters Stage 1 verifier semantics.

### 5.2 Epoch rollover [SPECIFIED — R2, NOT IMPLEMENTED]

Epoch rollover is also registry-driven. Illustrative policy: the current epoch
is accepted; the previous epoch is accepted only within a configurable grace
window (to accommodate key-distribution propagation delay); a future epoch is
rejected unless explicitly pre-authorized; and multiple simultaneously-active
`T_E` for one device/epoch are treated as a registry conflict to be escalated.

The verifier does not know the rollover policy. It validates the cryptographic
correctness of whatever epoch the frame carries; the registry decides whether
that epoch is currently authorized.

### 5.3 Epoch-velocity anomaly detection — honest limits [ARCHITECTURE — COMMITTED, with stated limit]

The registry can monitor epoch-advancement velocity per device. Abnormal
advancement — a device minting epochs faster than its legitimate schedule, or
two valid `T_E` for overlapping epochs — is a misuse signal that the registry
can flag and act on.

Stated limit, consistent with the threat model: velocity detection catches a
**greedy** attacker. It does **not** detect a **patient** attacker who mimics
the legitimate device's cadence. No registry-side heuristic detects a quiet,
cadence-matching compromise; only hardware-backed signing (Section 3.4)
addresses that case. This is documented as a *misuse-detection* signal, not as
*compromise detection*, and the distinction must be preserved in any deployment
claim.

### 5.4 Decision table [ARCHITECTURE — COMMITTED]

The composed outcome as a table, for operational legibility:

| Stage 1 result | Stage 2 state | Final result | Reason |
|---|---|---|---|
| `CRYPTO_REJECT` | (any) | Reject | Invalid frame or signature |
| `CRYPTO_ACCEPT` | `POLICY_ACTIVE` | Accept | Valid frame + authorized state |
| `CRYPTO_ACCEPT` | `POLICY_REVOKED` | Reject | Valid signature from revoked device/epoch/key |
| `CRYPTO_ACCEPT` | `POLICY_EXPIRED` | Reject | Valid signature outside the policy/epoch window |
| `CRYPTO_ACCEPT` | `SNAPSHOT_STALE` | Reject / Review | Registry freshness failure |
| `CRYPTO_ACCEPT` | `ATTESTATION_REQUIRED` | Review / Reject | Policy demands higher assurance than supplied |

Whether `SNAPSHOT_STALE` and `ATTESTATION_REQUIRED` resolve to hard-reject or
to a review/escalation path is a deployment policy choice; the committed point
is that they are distinct, named states, not silent accepts.

### 5.5 Typed reason codes [ARCHITECTURE — COMMITTED]

Mirroring R1's typed error codes, Stage 2 emits a typed reason code, not merely
a binary AUTHORIZED / NOT AUTHORIZED. The reason code becomes part of the
`policy_digest` evidence (Section 2.3) and makes the policy layer auditable.
Illustrative set:

```
POLICY_ACTIVE
POLICY_REVOKED_DEVICE
POLICY_REVOKED_EPOCH
POLICY_REVOKED_TE_HASH
POLICY_EXPIRED_EPOCH
POLICY_FUTURE_EPOCH
REGISTRY_SNAPSHOT_STALE
REGISTRY_SIGNATURE_INVALID
REGISTRY_CONFLICT
ATTESTATION_REQUIRED
ATTESTATION_INVALID
```

The exact enumeration is R2 design work; the committed principle is that Stage 2
decisions carry typed, auditable reasons.

---

## 6. Attestation Trust Roots and Their Failure Modes

A composition that depends on hardware attestation inherits the trust and
failure modes of the attestation infrastructure. This must be documented
precisely rather than assumed away.

### 6.1 Inherited trust [ARCHITECTURE — COMMITTED to documenting]

When the registry verifies a TPM quote, a WebAuthn attestation, or a cloud TEE
document, its security depends on:

- the correctness of the relevant hardware manufacturer's attestation keys and
  their certificate chains;
- the correctness of the attestation specification itself (TCG, FIDO, PSA, the
  cloud provider's attestation design);
- the correctness of the registry's own attestation-verification implementation.

These are normal dependencies for any attestation-consuming system, and they are
acceptable — but they are real, and a deployment's threat model must enumerate
them. A future revision of `fips/threat_model.md` will add an
attestation-trust-roots section once the integration is built; until then this
section is the placeholder statement of those inherited dependencies.

### 6.2 Failure modes to plan for [SPECIFIED — R2, NOT IMPLEMENTED]

- Manufacturer root-key rotation or compromise (revocation and re-enrollment
  policy needed).
- Attestation-format deprecation or version sunset (which TPM versions, which
  WebAuthn attestation formats are trusted, and how that set evolves).
- Verification-library vulnerabilities in the registry (the registry is itself
  security-sensitive software with its own attack surface).

These are enumerated here so that a reviewer can see they are anticipated. Their
resolution is R2 design work.

---

## 7. The Stage 2 Security Burden

### 7.1 The attack surface shifts to the registry [ARCHITECTURE — COMMITTED consequence]

A direct and important consequence of keeping R1 narrow, deterministic, and
secret-free is that the **primary application attack surface shifts to Stage 2**.
R1 remains a small C-ABI verifier processing public data; the registry and
policy gate, by contrast, parse signed snapshots, validate freshness, enforce
revocation, evaluate epoch rollover, handle attestation references, and emit
policy decisions. That is conventional, security-sensitive application
infrastructure.

This is the correct trade — concentrating mutable trust logic in one auditable
layer rather than smearing it into the verifier — but it must be named, not
hidden. Stage 2 requires conventional application-security hardening, including:

- strict schema validation of registry snapshots and inputs,
- signature verification on every registry snapshot,
- replay protection and monotonic `registry_sequence` enforcement,
- authorization controls on registry mutation,
- audit logging of policy decisions (the `policy_digest` supports this),
- dependency review of the registry service's own supply chain,
- adversarial testing of the snapshot parser and freshness logic.

In short: R1 stays pure; Stage 2 handles mutable trust and therefore carries the
operational security weight. A deployment that hardens R1 but neglects Stage 2
has moved the risk, not removed it.

---

## 8. Privacy and Correlation Limits [ARCHITECTURE — COMMITTED to addressing, mechanics SPECIFIED]

Composition with a registry and hardware attestation introduces privacy
considerations that the bare verifier does not have, and these align with
AN-DNA's minimum-necessary-trust philosophy. Stable device identifiers
(`device_id32`), attestation evidence, hardware-instance identity, and registry
history can become sensitive operational metadata:

- A stable `device_id32` can enable cross-context tracking of a device.
- Raw attestation evidence may reveal a device's vendor, model, or firmware
  class.
- Registry history can accumulate a behavioral record of a device's activity.

Design directions (mechanics deferred to R2):

- Registry snapshots should expose the minimum fields required for the policy
  decision, not the full device record.
- Public verifiers should not receive raw attestation evidence unless a specific
  deployment requires it; where possible, Stage 2 should operate on attestation
  *references* or *hashes* rather than raw quotes.
- Where unlinkability matters, the design space includes per-context identifiers
  or privacy-preserving attestation, but these are not specified here and would
  be deployment-specific.

The committed point is that minimum-necessary-disclosure applies to the registry
and attestation layers exactly as it applies to the verifier; the specific
privacy mechanics are R2 design work.

---

## 9. What This Composition Does Not Claim

Consistent with the threat model's non-claims, this integration model does
**not** claim:

- That hardware attestation is implemented in AN-DNA R1. It is not; R1 is the
  verifier.
- That enrollment-time attestation closes the A8 quiet-compromise case. It
  closes new-device forgery and bounds existing-device compromise via
  revocation; full closure requires hardware-backed signing (Section 3.4).
- That the registry, policy gate, or revocation mechanism exists. They are
  specified, not built.
- That any specific hardware, TPM version, attestation format, or anchoring
  substrate is selected. Those are deployment choices, deliberately deferred.
- That consuming attestation removes the registry's own attack surface. The
  registry is security-sensitive software with inherited trust dependencies
  (Section 6).
- A formal security proof of the composition. The verifier's properties are
  defined; the composed system's properties depend on R2 components that do not
  yet exist and on the prover-side D0 review that has not yet occurred.

---

## 10. Relationship to the Verifier and the Roadmap

### 10.1 R1 stays unchanged [ARCHITECTURE — COMMITTED]

This composition requires **no change to the R1 verifier**. The verifier's
value is its narrow, deterministic, secret-free design; the cleaner it stays,
the cleaner the composition. Attestation hooks are deliberately *not* added to
the verifier or the frame format. This is a committed constraint, not an
oversight.

### 10.2 Reframed R2 [ARCHITECTURE — COMMITTED direction]

This document reframes R2 from a pure scaling exercise (a Rust verifier service)
into a **trust-composition** effort:

1. the deterministic verifier from R1 (done);
2. a hardware-attested device registry (Section 3, Pattern 1);
3. a signed policy gate implementing Stage 2 (Sections 2, 5);
4. production deployment patterns, including the verifier service.

The verifier service is part of R2, but it is not the headline. The headline is
trust composition: AN-DNA does its narrow thing extremely well and composes
cleanly with the rest of the modern device-trust stack.

### 10.3 A sensible first R2 slice [SPECIFIED — R2, NOT IMPLEMENTED]

The composition above covers a lot of ground. To keep R2 executable, a sensible
first slice builds the registry/policy gate *without* blocking on
hardware-ecosystem maturity: a signed registry snapshot with device status
(`active | revoked | expired`), registered `device_id32` / `epoch` / `T_E_hash`,
`registry_sequence` freshness, the Stage 2 decision engine, and the
`policy_digest` — with attestation represented by a placeholder
`attestation_status = not_integrated` field. A subsequent increment adds one
real attestation format (likely TPM 2.0 or WebAuthn, depending on the first
design partner) through the RATS/EAT appraisal interface.

This is framed as a *sensible first slice*, not a committed timeline or
deliverable. It demonstrates that the registry/policy layer can be built
incrementally and does not depend on per-operation hardware-backed signing.

| Capability | First R2 slice | Later R2 |
|---|---|---|
| Signed registry snapshot | Yes | Yes |
| Revocation | Basic deny-list | Distributed sync |
| Epoch rollover | Current / previous policy | Advanced grace windows |
| Hardware attestation | Placeholder field | WebAuthn / TPM 2.0 / RATS-EAT integration |
| Per-operation attestation | No | Optional high-assurance profile |
| Hardware-backed PQ signing | No | Future, ecosystem-dependent |
| `policy_digest` | Yes | Yes |
| Rust verifier service | Optional | Yes |

### 10.4 Dependencies on external review [IMPLEMENTED — R1 context]

The composition's production security still depends on the prover-side D0
epoch-witness bridge, which is outside the verifier codebase and requires
independent cryptographic review (threat model R2). Hardware attestation
addresses *where keys live and how devices enroll*; it does not substitute for
review of *how epoch keys are derived*. Both are required before
production-security claims about the full system.

---

## 11. Future Work

Tracked separately from the R1 verifier boundary. Composition-specific items:

1. Registry/policy-gate specification: signed-snapshot schema, freshness
   guarantees, distribution and synchronization to distributed verifiers.
2. RATS/EAT appraisal interface specification for the registry, with the first
   concrete underlying format (likely WebAuthn or TPM 2.0, depending on the
   first deployment).
3. Attestation-trust-roots section for `fips/threat_model.md`, added once the
   integration is built.
4. Per-operation attestation profile (Section 3.3) for high-value operations.
5. Evaluation of hardware-backed PQ signing (Section 3.4) as the ecosystem
   matures.
6. Hybrid-signature consideration (classical + ML-DSA-44) for deployments under
   transition mandates that require it.

---

## 12. Summary

AN-DNA R1 is a deterministic post-quantum verifier and evidence artifact. It
proves key possession over a canonical payload; it does not, and by design
cannot, prove that the key was generated and used inside trusted hardware or
that the device is currently authorized.

This document specifies how those out-of-scope assumptions are intended to be
discharged in production through composition: hardware-attested device
enrollment (consuming standards-based remote attestation through a RATS/EAT
appraisal interface), bound to a device registry, evaluated by a signed Stage 2
policy gate that handles revocation and epoch rollover — all *around* the
verifier, never *inside* it, preserving the determinism that makes the verifier
valuable.

The committed architecture is the two-stage separation, the
attestation-as-consumed-standard position, and the no-change-to-R1 constraint.
Everything below that — specific schemas, formats, versions, substrates, and the
registry implementation itself — is R2 design work, deliberately deferred. The
production security of the composed system additionally depends on independent
review of the prover-side D0 bridge, which remains the gating external-review
item.

> AN-DNA is a trust component, not a trust system. It contributes deterministic
> post-quantum verification and composes with a hardware root of trust, a
> standards-based attestation step, and a registry/policy gate to produce the
> production trust property that no single component provides alone.

---

## 13. Note on Use

This document is suitable for technical design-partner review as a composition
blueprint. It should be read alongside `fips/threat_model.md` (the verifier
boundary) and the rest of the FIPS package. It is **not** a deployment claim:
the registry, policy gate, and hardware-attestation integration it describes are
R2 design work, not shipped or validated components. AN-DNA R1 — the verifier —
is the only part described here that exists today.

---

## 14. References

External standards and specifications referenced in this document. These are the
standards the composition would consume (Section 4) or the cryptographic
foundations it builds on; a reviewer can verify the claims against them.

- **NIST FIPS 204** — Module-Lattice-Based Digital Signature Standard (ML-DSA).
  The signature algorithm verified by R1.
- **NIST FIPS 203** — Module-Lattice-Based Key-Encapsulation Mechanism Standard
  (ML-KEM). Referenced in the context of TPM 2.0 v1.85 PQC support; not used by
  R1 (which is signature-only).
- **IETF RFC 9334** — Remote ATtestation procedureS (RATS) Architecture. The
  primary attestation appraisal framework targeted in Section 4.
- **IETF EAT** — Entity Attestation Token (draft / RATS WG). The attestation
  claims-token format targeted as the appraisal interface.
- **W3C WebAuthn (Level 3)** — Web Authentication, including attestation
  conveyance. A consumable underlying attestation format.
- **TCG TPM 2.0 Library Specification** — including v1.85, which adds ML-DSA
  (attestation-key use) and ML-KEM (endorsement-key use) and sequence-based
  signing commands for large messages. A consumable underlying attestation
  source; also relevant to the hardware-backed-signing discussion (Section 3.4).
- **ARM PSA Attestation Token (PSA-AT)** — Platform Security Architecture
  attestation. A consumable underlying attestation format for ARM ecosystems.
- **Cloud TEE attestation** — e.g. AWS Nitro attestation documents, Google
  Confidential VM attestation, Microsoft Azure Attestation. Consumable
  underlying attestation sources for TEE-based cloud deployments.
- **Mobile attestation** — Android Key Attestation; Apple App Attest /
  DeviceCheck. Consumable underlying attestation formats for mobile fleets.

These are referenced as integration targets and foundations. Listing a standard
here is not a claim that the integration is implemented; per Section 0, the
attestation integrations are SPECIFIED (R2), not shipped.

---

## 15. Revision History

| Version | Date | Change |
|---|---|---|
| 1.0.0 | 2026-05-30 | Initial trust-composition / integration model. Companion to the verifier threat model. Medium scope: hardware-attested device enrollment (Pattern 1) as the primary A8 mitigation, the two-stage registry/policy gate extended from threat-model Section 6.5, and attestation trust roots and their failure modes. Standards-based consumption with IETF RATS/EAT as the primary appraisal interface and WebAuthn / TCG TPM 2.0 / ARM PSA-AT / cloud-TEE / mobile attestation as consumable underlying formats. Status labels distinguish IMPLEMENTED (R1), ARCHITECTURE-COMMITTED, and SPECIFIED (R2, not implemented) throughout. Explicit non-claims aligned with the threat model: enrollment-time attestation closes new-device forgery and bounds existing-device compromise but does not close the quiet-compromise case (which requires hardware-backed signing); registry/policy/revocation specified but not built; no specific hardware/version/substrate selected; composition security still gated on D0 bridge review. |
| 1.0.1 | 2026-05-30 | Tightening pass after three independent reviews. Added: a `policy_digest` recipe (Section 2.3); a composition diagram and a Stage 1/Stage 2 decision table (Sections 2.1, 5.4); typed Stage 2 reason codes (Section 5.5); a "Stage 2 Security Burden" section noting the attack surface shifts to the registry (Section 7); a "Privacy and Correlation Limits" section (Section 8); and a sensible-first-R2-slice boundary with an MVP-vs-later table (Section 10.3). Tightened the enrollment-attestation claim to distinguish enrollment-time provenance from continuous non-extraction (Section 3.1); added explicit conditions under which hardware-backed signing closes A8 — non-exportable key, attested signing path, trusted root, correct policy (Section 3.4); and corrected the PQ-hardware-availability note to reflect the TCG TPM 2.0 v1.85 specification (ML-DSA / ML-KEM, sequence-based signing commands) while preserving the operational caveat that commodity deployed hardware should not be assumed to support ML-DSA-44 signing today (Section 3.4). Added a Note on Use (Section 13). No change to the committed architecture or to R1. |
| 1.0.2 | 2026-05-30 | Final cleanup pass before lock, after a fourth review. Added a References section (Section 14) listing the external standards the composition consumes or builds on (FIPS 203/204, RATS RFC 9334, EAT, WebAuthn L3, TCG TPM 2.0 / v1.85, ARM PSA-AT, cloud-TEE and mobile attestation). Added a requirement that R2 define a canonical serialization for `canonical_policy_record` (field ordering, encoding, timestamp representation, integer widths, hash algorithms) before `policy_digest` is treated as reproducible evidence (Section 2.3). Clarified that on `CRYPTO_REJECT`, Stage 2 is not evaluated and `policy_digest` is null/absent, with the decision anchored solely by `verification_digest` (Section 2.1). Refined the `policy_digest` record to identify content, signer, and signature instance separately (`registry_snapshot_hash`, `registry_issuer_id`, `registry_signature_hash`), replacing the prior `issuer_signature_hash` which hashed only the signature bytes (Section 2.3). No change to the committed architecture or to R1. |