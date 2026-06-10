# AN-DNA File-Seal Evidence v1

Status: implemented and CI-gated  
Schema version: `andna-seal-evidence-v1`  
Primary producer: `andna verify-file --evidence-out <path>`

## Purpose

`andna-seal-evidence-v1` is the stable evidence record produced by the file-seal verifier. It records one replayable trust decision over a sealed object.

The evidence answers four operator questions:

1. Was the seal authentic?
2. Was the file unchanged relative to the sealed manifest?
3. Was the sealing identity authorized by the supplied registry snapshot?
4. Was the final result `ACCEPT` or `REJECT`?

This is not just a raw signature result. The record preserves the combined decision across the file/object layer, R1 verification, and R2 authorization.

## Evidence model

The full evidence object has this top-level shape:

```json
{
  "schema_version": "andna-seal-evidence-v1",
  "deterministic": {},
  "evidence_digest_hex": "...",
  "runtime": {},
  "display_summary": "..."
}
```

The design separates replayable decision facts from environment facts.

| Section | Purpose | Digest input? | Stability expectation |
| --- | --- | --- | --- |
| `schema_version` | Identifies the evidence contract. | No | Stable for v1. |
| `deterministic` | Replayable decision core. | Yes | Must reproduce for the same bundle, file bytes, and registry snapshot. |
| `evidence_digest_hex` | SHA3-256 digest of the canonical deterministic section. | N/A | Must reproduce when `deterministic` reproduces. |
| `runtime` | Paths, tool version, timestamp, and other machine-local facts. | No | May differ across machines and runs. |
| `display_summary` | Human-readable presentation string. | No | Informational only. |

## Deterministic section

The deterministic section is the replayable core. It is a pure function of:

```text
sealed bundle + file bytes presented to verification + registry snapshot
```

Current fields:

| Field | Type | Meaning |
| --- | --- | --- |
| `result` | string | `ACCEPT` or `REJECT`. |
| `authentic` | bool | R1 authenticity verdict. |
| `unchanged` | string | `yes`, `no`, or `not_evaluated`. |
| `unchanged_detail` | string/null | Reason for unchanged failure, such as `file_hash_mismatch` or `manifest_hash_mismatch`. |
| `authorized` | string | `yes`, `no`, or `not_evaluated`. |
| `reason_code` | string | R2 reason code, such as `registry_entry_valid`, `no_registry_entry`, or `stage1_reject`. |
| `verify_error` | string/null | R1 verification error when authenticity fails. |
| `file_hash_hex` | string | SHA3-256 hash of the file bytes presented to verification. |
| `frame_hash_hex` | string | SHA3-256 hash of the exact R1 frame bytes. |
| `manifest_hash_hex` | string/null | Canonical manifest hash when available. |
| `frame_ctx_hash_hex` | string/null | `ctx_hash` carried in the accepted frame when available. |
| `epoch` | integer | Verified epoch associated with the sealing identity. |
| `device_id32_hex` | string | Verified 32-byte device identity. |
| `te_hash_hex` | string | Verified SHAKE256-64 hash of the T_E structure (epoch public key || epoch || device_id16), carried as the frame's pk_hash binding and confirmed by R1. |
| `attestation_status` | string | R2 attestation status recorded in the decision. |
| `registry_policy_version` | string | Policy version from the registry snapshot. |
| `entry_policy_version` | string/null | Policy version on the matching registry entry, when present. |
| `snapshot_seq` | integer | Registry snapshot sequence used for the decision. |
| `as_of_unix_ms` | integer | Registry snapshot effective time. |
| `registry_snapshot_hash_hex` | string | Hash of the registry snapshot used for authorization. |
| `policy_digest_hex` | string/null | Snapshot-bound R2 policy digest when policy was evaluated. |

Field shape on R1 reject
When authentic is false (R1 rejected the frame), the record has a defined reject shape:

unchanged and authorized are not_evaluated (fail-closed: an unauthentic frame's
ctx_hash is not trustworthy, and R2 policy is not evaluated).
manifest_hash_hex and frame_ctx_hash_hex are null.
epoch is 0 and device_id32_hex / te_hash_hex are zero-filled. These zeros mean
"no verified identity facts exist for this frame" — they are NOT real identity values.
policy_digest_hex is null; reason_code is stage1_reject; verify_error carries the
R1 error string (e.g. signature_invalid).
The registry snapshot fields still describe the supplied registry, since the decision
"NOT_EVALUATED" was made against that snapshot.

## Runtime section

The runtime section records useful local facts without changing replayability.

Current fields:

| Field | Type | Meaning |
| --- | --- | --- |
| `file_path` | string/null | Local path of the verified file. |
| `seal_path` | string/null | Local path of the sidecar seal. |
| `registry_path` | string/null | Local path of the registry snapshot. |
| `tool_version` | string/null | CLI/tool version that produced the evidence. |
| `verified_at_unix_ms` | integer/null | Local verification time. |

Runtime fields are intentionally excluded from `evidence_digest_hex`. Two operators verifying the same file, seal, and registry from different directories should be able to produce the same deterministic section and the same evidence digest.

## Digest rule

`evidence_digest_hex` is computed as:

```text
SHA3-256(domain-separated canonical encoding of deterministic)
```

The digest is not computed over JSON. This prevents harmless JSON formatting changes from changing the evidence digest.

The canonical encoding uses:

- domain separation: `ANDNA-SEAL-EVIDENCE-v1`
- fixed field order
- length-prefixed strings
- explicit option tags for absent/present optional fields
- little-endian integer encoding

For v1, do not reorder deterministic fields. Additive changes require a new schema version unless the contract explicitly reserves the field.

## Replay rules

A verifier, auditor, or second operator can treat an evidence record as replay-consistent when:

1. `schema_version == "andna-seal-evidence-v1"`
2. `digest_consistent()` succeeds, or an equivalent recomputation produces `evidence_digest_hex`
3. the deterministic section matches the independently replayed verification result
4. runtime differences are ignored unless the investigation specifically concerns local execution context

## Tamper expectations

Editing deterministic fields must break digest consistency unless the attacker also recomputes the digest. If the evidence file itself is sealed and attested, editing deterministic fields should also make the attested evidence file verify as `UNCHANGED: no` and `RESULT: REJECT`.

Editing runtime fields does not break digest consistency because runtime fields are outside the digest by design.

## Contract tests

The evidence contract tests enforce:

- deterministic section replay across repeated verification
- digest equality across repeated verification
- runtime field independence
- digest sensitivity when the decision changes
- authorization failure isolation
- JSON roundtrip preservation
- detection of edited deterministic sections

Run:

```bash
cargo test -p andna-seal --test evidence_contract -- --nocapture
```

The CI file-seal lane also runs the seal library tests and the operator-level CLI contract.

## Versioning rule

For `andna-seal-evidence-v1`:

- field names are part of the contract
- deterministic field order is part of the canonical digest contract
- runtime fields are informational and digest-exempt
- display text is informational and digest-exempt
- incompatible deterministic changes require a new schema version

## Claim boundary

This evidence record proves what AN-DNA evaluated and what decision it produced under the supplied inputs. It does not claim that the local software-profile sealer is hardware-backed, clone-resistant, enterprise IAM-integrated, or FIPS-validated.
