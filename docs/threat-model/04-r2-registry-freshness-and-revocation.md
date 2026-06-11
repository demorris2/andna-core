# 04 — R2 Registry Freshness and Revocation

## Built / true today

R2 evaluates authorization against the **supplied** registry snapshot. The registry snapshot
is an operator-supplied JSON file; R2 does not fetch or verify it from a network authority.

### Authorization checks (applied in this order after R1 ACCEPT)

1. Fail-closed gate: if R1 rejected, R2 returns `NOT_EVALUATED` (`stage1_reject`).
   Authorization logic does not run on a CRYPTO_REJECT.
2. Device lookup by `device_id16` — failure: `no_registry_entry`.
3. Revocation flag — failure: `device_revoked` (highest-severity rejection; takes precedence
   over all other failures).
4. Frozen flag — failure: `lineage_frozen`.
5. Recovery-hold flag — failure: `recovery_hold`.
6. Epoch freshness — frame epoch must equal entry's `current_epoch` — failure: `epoch_stale`.
7. te_hash authorization — frame's `te_hash` must be in entry's `authorized_te_hashes` list —
   failure: `te_not_authorized`.

If all checks pass: `AUTHORIZED` / `registry_entry_valid`.

### Evidence bound into policy_digest

On every authorization decision R2 computes a SHA3-256 policy digest over:
- The full R2 decision outcome.
- The registry snapshot (snapshot_hash is a SHA3-256 over sorted entry hashes; independent
  of entry order in the JSON).

This digest is recorded in evidence and changes if the decision or the snapshot changes,
even if the overall verdict (AUTHORIZED vs NOT_AUTHORIZED) is the same.

R2 records `snapshot_seq`, `as_of_unix_ms`, and `snapshot_hash` in every decision. These
fields are deterministic and reproducible.

### Policy version

`policy_version` fields on the registry and on individual entries are informational. R2 does
not currently enforce version consistency between the registry-level and entry-level
policy_version values. Both are captured in the policy digest.

## Threat analysis

### Stale snapshot

An operator may supply a snapshot that is days or weeks old. R2 evaluates authorization
against whatever snapshot is supplied. If a device was revoked in a newer snapshot but the
operator presents an old one, R2 will authorize.

**Current mitigation:** `as_of_unix_ms` and `snapshot_seq` are recorded in evidence, giving
auditors the information to detect staleness after the fact. **Gap:** R2 does not refuse to
authorize against a snapshot older than a configured freshness window.

### Rolled-back snapshot

A root adversary who controls the registry file can replace a current snapshot with an older
one to resurrect a revoked device. R2 cannot detect this because it has no monotonic floor
on `snapshot_seq`.

**Current mitigation:** evidence records `snapshot_seq` and `snapshot_hash` — a tampered
registry will produce a different hash, detectable by an auditor who compares against a
known-good hash. **Gap:** no real-time enforcement; detection is post-hoc only.

### Revoked device accepted under old snapshot

See "Stale snapshot" above. The only real-time protection is the operator discipline of
keeping the registry file current and distributing updated snapshots to all verifier nodes
promptly after a revocation event.

### Policy-version mismatch

R2 does not currently check that the registry's `policy_version` matches the entry's
`policy_version`. An entry from a future or past policy schema version will be processed
by the current authorization logic without a version gate. Both versions are captured in
the policy digest for audit purposes but no rejection occurs.

### Authorization on partial identity

R2 matches on `device_id16` (16 bytes). If two devices share a `device_id16` prefix by
collision or operator error, R2 will evaluate the first matching entry. The full 32-byte
`device_id32` is not the primary lookup key in the current implementation.

### Over-broad registry entry

If an entry's `authorized_te_hashes` list includes stale or revoked keys (keys from prior
epochs that have not been pruned), R2 will authorize frames signed by those keys as long as
the epoch and device_id checks pass.

### Split verifier state

If two operators run R2 with different registry snapshots simultaneously, they can disagree
on whether a device is currently authorized. Without a signed snapshot root or a
`snapshot_seq` monotonicity floor, neither operator can prove the other is wrong.

**Key wording:** R2 does not prove global or current authorization unless snapshot freshness
and authority are separately established. That is an external assumption in the current MVP.

## Not yet built (future mitigations)

- Signed snapshots (registry authority signs each snapshot; R2 refuses unsigned or
  unrecognized-signer snapshots).
- `snapshot_seq` monotonicity floor (R2 refuses a snapshot whose `snapshot_seq` is lower
  than the last-seen value — the "Monotonic-Epoch-Guard" concept).
- `as_of_unix_ms` freshness window (R2 warns or refuses snapshots older than N hours).
- `valid_from` / `valid_until` per entry (time-bounded authorization without full revocation).
- Revocation timestamp (enables auditors to prove a specific device was revoked before a
  specific verification event).
- Witnessed checkpoint (an online witness cosigns snapshot sequences, enabling non-repudiation).
- Staleness indicator in evidence (R2 flags snapshots that are older than a configured
  threshold without refusing to authorize).

## Reviewer questions

1. Should the "revoked device accepted under old snapshot" threat be flagged as a critical
   gap for any production deployment, or is the evidence-record approach sufficient for the
   current pilot scope?
2. Is the device_id16 vs device_id32 lookup ambiguity worth raising as a design concern,
   or is the collision probability under controlled enrollment acceptably low?
