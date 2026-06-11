# 05 — Evidence Semantics and Replay

## Built / true today

The evidence schema is `andna-seal-evidence-v1`. The evidence record has two sections:

- **Deterministic section**: fields whose values are identical across repeated verifications
  of the same (file, sidecar, registry) triple. Includes: `result`, `authentic`, `unchanged`,
  `authorized`, `file_hash_hex`, `manifest_hash_hex`, `frame_hash_hex`, `epoch`,
  `device_id16_hex`, `snapshot_seq`, `registry_snapshot_hash_hex`, `reason_code`,
  `unchanged_detail`, `policy_digest_hex`.
- **Runtime section**: fields that vary by machine or time: `file_path`, `seal_path`,
  `registry_path`, `tool_version`, `verified_at_unix_ms`.

The `evidence_digest_hex` is SHA3-256 over the canonical bytes of the **deterministic section
only**. Runtime fields do not affect the digest.

## Precise action semantics

### `check-evidence <evidence.json>` (specified contract)

Recomputes the SHA3-256 digest over the deterministic section of the evidence file and
compares it to the stored `evidence_digest_hex`. Detects in-place edits to deterministic
fields (e.g. flipping REJECT to ACCEPT in the JSON). Does **not** perform cryptographic
re-verification of the original file, sidecar, or frame.

**`digest_consistent()` is not replay.** A passing digest check means the stored record is
internally coherent. It does not re-evaluate whether the underlying file, sidecar, or
registry state still produces the same verdict.

Note: if the `check-evidence` CLI command is not yet implemented, this documents its
specified contract, not a shipped feature.

### `replay --file <f> --seal <s> --registry <r> --against <evidence.json>`

Re-runs the full CLI verification pipeline on the original inputs and compares the resulting
deterministic section to the evidence record. Produces MATCH or MISMATCH.

Full replay **requires the original inputs** — the file bytes, the sidecar JSON, and the
registry snapshot used at signing time. Without all three, replay cannot be performed.

**The evidence JSON alone does not replay.** This is a load-bearing statement. Do not write
or imply that an evidence file is self-verifying.

Note: if the `replay` CLI command is not yet implemented in this form, this documents its
specified contract.

## Threat analysis

### Evidence file tamper (post-issuance edit)

An adversary edits the evidence JSON to change `result` from REJECT to ACCEPT. Running
`check-evidence` on the tampered file will return FAIL because the recomputed digest will not
match the stored `evidence_digest_hex`. The `digest_consistent()` method detects this.

**Covered:** characterization test `digest_consistent_detects_edited_deterministic_section`
asserts this behavior.

### Evidence substitution

An adversary discards the legitimate evidence file and produces a new one by re-running
verification on a different (forged) file. If they hold signing material, they can produce a
valid ACCEPT evidence record for a forged artifact. The evidence-attestation flow (sealing
the evidence record itself as an artifact) allows an operator to prove a specific evidence
file was not replaced, but only if the attestation was captured at issuance.

**Current mitigation:** evidence attestation (sealed evidence); detects post-seal replacement.
**Gap:** requires the operator to have sealed the evidence at issuance time; not automatic.

### Replay without original inputs

An auditor presents only the evidence JSON and claims it proves a file was verified. Without
the original file, sidecar, and registry, this claim cannot be fully replicated. The evidence
digest only proves the stored record is coherent, not that the original inputs would
reproduce the same verdict under a fresh run.

**Operator guidance:** for replay-capable audit records, retain the original inputs alongside
the evidence file.

### Runtime-field manipulation

An adversary edits `file_path` or `tool_version` in the evidence JSON. `digest_consistent()`
returns OK because runtime fields are outside the digest. This is expected behavior —
runtime fields are explicitly excluded from the evidence contract.

**Guidance:** do not rely on runtime fields for security decisions. The digest covers only
the deterministic section.

## Not yet built (future mitigations)

- `check-evidence` CLI command (the specified contract above is not yet a shipped subcommand;
  the library function `digest_consistent()` exists).
- `replay --against` CLI command (specified above; not yet a shipped subcommand).
- Automatic evidence attestation at seal time (today it is a manual operator step).
- Evidence signing by a second party (co-signature or timestamp from an external authority).

## Reviewer questions

1. Is the distinction between `digest_consistent()` and full replay clear enough for an
   operator who may not read the source? Should the evidence JSON itself carry a human-readable
   "replay requires original inputs" field?
2. The `check-evidence` and `replay` CLI subcommands are specified here but not yet shipped.
   Should they be tracked as R1.1 scope items?
