# R1 Feature Freeze

**Effective:** 2026-02-27
**Status:** LOCKED
**Change control:** ADR + backlog only. No exceptions.

## Locked Scope (Non-Negotiable)

| Constant              | Value              | Source                     |
|-----------------------|--------------------|----------------------------|
| mu_pre length         | 274 bytes          | `andna_contracts::MU_PRE_LEN` |
| Frame V2 length       | 4030 bytes         | `andna_contracts::FRAME_V2_LEN` |
| Domain separator      | `ANDNAAUTH` (9B)   | `andna_contracts::DOMAIN_SEP` |
| Version byte          | `0x01`             | `andna_contracts::MU_PRE_VERSION_VAL` |
| Transcript hash       | SHAKE256           | `andna_transcript` crate |
| ML-DSA-44 parameters  | FIPS 204 Category 2 | `andna_mldsa44` crate |
| T_E size              | 1338 bytes         | `andna_contracts::TE_LEN` |
| Signature size        | 2420 bytes         | `andna_contracts::SIG_LEN` |
| PK hash size          | 64 bytes           | `andna_contracts::PK_HASH_LEN` |

### Deliverables

- [x] Rust core workspace (7 crates, 46 tests passing)
- [x] Python bindings (78+ tests passing)
- [x] FFI boundary with panic safety (Directive C)
- [x] Security directives A-E implemented and verified
- [x] Replay CLI (`python -m andna verify/replay/export`)
- [x] Deterministic structured logging (JSON to stderr)
- [x] Evidence bundle export (evidence.json + manifest.json + SHA-256 integrity)
- [ ] Docker reproducible release lane
- [ ] SBOM generation
- [ ] NIST ACVP vectors embedded (download script ready)

## Allowed Improvements

- CI reproducibility hardening
- Logging clarity
- CLI UX polish
- Installation friction reduction
- Documentation refinement
- Test coverage expansion

## Forbidden (6 Months)

- New protocol primitives
- Governance runtime expansion
- Autonomy logic
- Multi-vertical messaging
- Additional SKUs
- Changes to contract constants without ADR

## Acceptance Criteria (Binary)

R1 is complete when:

1. Fresh clone → build → verify → replay → identical output
2. 5-minute demo passes without explanation
3. Evidence bundle exportable and integrity-verifiable
4. Deterministic across clean machines
5. 1 external validation conversation (Month-4 gate)

Everything else is ornamental.
