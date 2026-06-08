# AN-DNA Access Control Positioning

## Summary

AN-DNA is a ratcheting authorization evidence system for digital objects, credentials, devices, and access requests.

The current implementation proves the local decision chain through a practical file-seal workflow:

```text
file/object
→ manifest hash
→ signed R1 context hash
→ R1 cryptographic verification
→ R2 policy authorization
→ replayable decision evidence
```

The long-term access-control direction is broader:

```text
identity or credential state
→ ratcheted epoch key
→ signed access request
→ R1 verification
→ R2 authorization
→ audit record
→ replayable access decision
```

AN-DNA is not a replacement for RSA, FIDO2, IAM, smart cards, HSMs, or physical access-control systems. It is a trust-evidence layer that can work alongside them.

The intended product claim is:

> AN-DNA turns credentials, devices, files, and access requests into replayable authorization evidence.

## Core Product Idea

Most access-control systems ask a narrow question:

```text
Is this credential valid?
```

AN-DNA is designed to ask a broader decision question:

```text
Is this request authentic?
Is the identity or credential current?
Is the signer authorized under policy?
Was the decision recorded?
Can the decision be replayed later?
```

This distinction matters because a valid signature does not always mean a valid authorization.

A credential may be cryptographically authentic but still be:

```text
revoked
stale
frozen
outside policy
outside the allowed epoch
not authorized for the requested resource
not authorized for the requested action
```

AN-DNA separates these concerns.

## R1, D0, R2, and Audit

AN-DNA’s access-control architecture is organized into distinct layers.

### D0 — Ratcheting Identity State

D0 represents the prover-side identity or credential state.

Its role is to derive epoch-specific signing material from a deterministic, ratcheting state.

In an access-control setting, D0 answers:

```text
What identity state produced this access request?
What epoch was used?
Does this request belong to the expected lineage?
```

D0 is the foundation for living credentials. Unlike a static key that remains unchanged, a D0-backed credential can advance through epochs.

### R1 — Cryptographic Verification

R1 verifies the signed frame.

Its role is to answer:

```text
Was this frame signed correctly?
Does the transcript bind the expected context?
Does the public key / T_E material match the signed request?
Does the frame pass the cryptographic checks?
```

R1 does not decide whether access should be granted. It only decides whether the cryptographic evidence is acceptable.

R1 output is conceptually:

```text
CRYPTO_ACCEPT
CRYPTO_REJECT
```

### R2 — Policy Authorization

R2 evaluates authorization policy after R1 accepts the cryptographic evidence.

Its role is to answer:

```text
Is this identity known?
Is the credential revoked?
Is the lineage frozen?
Is the credential on recovery hold?
Is the epoch current?
Is the T_E hash authorized?
Does policy allow the request?
```

R2 output is conceptually:

```text
AUTHORIZED
NOT_AUTHORIZED
NOT_EVALUATED
```

If R1 rejects, R2 should not authorize. The system fails closed.

### Audit — Replayable Decision Evidence

The audit layer records the decision chain.

Its role is to answer:

```text
What was verified?
What policy snapshot was used?
What decision was made?
Can the decision be replayed later?
Can tampering, deletion, duplication, or reordering be detected?
```

This is the difference between a simple access result and an evidence-backed access decision.

## Why This Matters for Access Control

Access-control decisions often become difficult to reconstruct after the fact.

Common questions include:

```text
Why was this person granted access?
Was the badge valid at the time?
Was the device still authorized?
Was this credential stale?
Was this action approved by policy?
Was the request signed by the expected authority?
Can we prove the access decision later?
```

AN-DNA is designed to preserve the decision path.

A future AN-DNA access-control event could look like this:

```text
Access Attempt 1:
credential epoch 100
R1: CRYPTO_ACCEPT
R2: AUTHORIZED
Audit: recorded

Access Attempt 2:
credential epoch 101
R1: CRYPTO_ACCEPT
R2: AUTHORIZED
Audit: recorded

Access Attempt 3:
credential epoch 102
R1: CRYPTO_ACCEPT
R2: NOT_AUTHORIZED
Reason: device_revoked
Audit: recorded
```

This creates a chain of access evidence, not just a pass/fail event.

## Digital Access Examples

Potential digital access-control use cases include:

```text
API access
developer deployment authority
admin approvals
service-to-service authentication
machine identity
secure document access
release artifact authorization
healthcare record access
internal compliance workflows
```

Example:

```text
A developer attempts to deploy software to production.

AN-DNA checks:
1. Is the request cryptographically authentic?
2. Does it bind to the expected request context?
3. Is the signer currently authorized?
4. Is the signer allowed to deploy this artifact to this environment?
5. Can the decision be replayed later?

Result:
AUTHORIZED or NOT_AUTHORIZED
```

## Physical Access Examples

Potential physical access-control use cases include:

```text
smart badge
building access card
secure room credential
field-device credential
portable authorization token
facility access checkpoint
```

Example:

```text
A badge is presented at a secure door.

AN-DNA checks:
1. Is the credential authentic?
2. Is the credential at the expected epoch?
3. Is the credential revoked, frozen, or stale?
4. Is this badge allowed through this door at this time?
5. Can the decision be replayed later?

Result:
ALLOW or DENY
```

This does not replace the physical reader, lock, badge hardware, or facility access software. It provides a cryptographic authorization evidence layer that can work with those systems.

## File Seal as the First Practical Use Case

The file-seal CLI is not the final access-control product. It is the first practical proof that AN-DNA can bind a real object into the decision chain.

The current file-seal workflow proves:

```text
A file can be sealed.
The file's manifest hash can be placed into the signed R1 context.
R1 can verify the signature and frame.
The seal layer can prove the file is unchanged.
R2 can determine whether the signer is authorized.
The result can be shown as AUTHENTIC / UNCHANGED / AUTHORIZED.
```

This is directly relevant to access control because access requests are also objects.

A future access request can use the same pattern:

```text
access request manifest
→ request hash
→ signed context hash
→ R1 verification
→ R2 authorization
→ access decision evidence
```

## What AN-DNA Can Say Today

Current implementation supports a local file-seal decision chain.

A precise statement is:

> AN-DNA can seal a file by binding its manifest hash into a signed R1 frame, then verify authenticity, unchanged content, and R2 authorization using local evidence.

Current CLI output:

```text
AUTHENTIC: yes
UNCHANGED: yes
AUTHORIZED: yes
RESULT: ACCEPT
```

This is a real local workflow.

## What AN-DNA Should Not Claim Yet

Until additional layers are implemented, AN-DNA should not claim:

```text
production-ready physical access control
replacement for RSA
replacement for FIDO2
replacement for IAM
replacement for smart cards
hardware-backed identity
clone resistance
global transparency
witness-backed non-equivocation
encryption
malware detection
```

The current system proves a local authorization decision chain, not a full enterprise access-control platform.

## Strongest Positioning Statement

The strongest current positioning is:

> AN-DNA is a post-quantum authorization evidence layer. It verifies authenticity, separates cryptographic acceptance from policy authorization, and records replayable evidence for why a file, credential, device, or access request was accepted or rejected.

## Short Product Language

```text
AN-DNA helps answer whether a digital object or access request is authentic, unchanged, authorized, and replayable as evidence.
```

## Longer Product Language

```text
AN-DNA is a ratcheting, post-quantum trust-evidence system for access decisions. It combines cryptographic verification, identity lineage, policy authorization, and audit replay so organizations can prove why something was accepted or rejected.
```

## Access-Control Future State

The next major product layer should be an AN-DNA access envelope.

Conceptual format:

```text
AccessRequest
- subject_id
- device_id
- resource_id
- action
- epoch
- nonce or challenge
- context hash
- signed R1 frame
- registry / policy reference
```

Conceptual commands:

```text
andna access-request --subject alice --resource door-7 --action enter
andna access-verify --request access.json --registry local_registry.json
```

Expected result:

```text
AUTHENTIC: yes
CURRENT: yes
AUTHORIZED: yes
RESULT: ALLOW
```

This is the access-control equivalent of the file-seal CLI.

## Recommended Product Evolution

The recommended path is:

```text
1. File Seal CLI
   Proves object binding and local authorization evidence.

2. Access Envelope MVP
   Binds an access request into the same R1/R2 decision chain.

3. Registry Snapshot / Verify-As-Of
   Supports historical authorization review.

4. Hardware-Attested Credential Profile
   Adds stronger custody and clone-resistance properties.

5. Witness / Transparency Layer
   Adds stronger non-equivocation and ecosystem-level trust.
```

## Bottom Line

AN-DNA should not be positioned as a new standalone cryptographic primitive.

It should be positioned as:

> A ratcheting authorization chain for proving whether something should be accepted right now, and why.
