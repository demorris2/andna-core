# AN-DNA R1 Evidence Artifacts (v1.0)

## Authoritative
**`andna_audit.jsonl`**
Canonical, tamper-evident chain. Fields include seq, prev_hash, record_hash. Used for all integrity claims.

**`audit_validate.json`**
Validator outcome for andna_audit.jsonl (PASS/FAIL + reason). Used as machine-checkable proof in CI.

## Convenience / Human-readable
**`verification_log.json`**
Human-friendly session record for replay UX. Not used for integrity claims.

## Evidence bundle
**`evidence.json`**
Structured export of verification records for audit packaging.

**`manifest.json`**
Contains digests (sha3-256) and the verification_digest used for cross-machine parity checks.

## How to validate tamper (one command)
Run the validator on `andna_audit.jsonl`.
If a single byte is changed → FAIL (demonstrated by T2).