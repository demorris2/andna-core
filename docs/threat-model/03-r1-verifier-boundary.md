# 03 — R1 Verifier Boundary

## Built / true today

R1 is the ML-DSA-44 public verifier. Engineering is complete; the remaining P0 item is an
external CST-lab ACVP session (not an engineering gap).

### Canonical frame layout (Frame v2)

| Region | Offset | Length | Description |
|---|---|---|---|
| `mu_pre` | 0 | 274 B | Transcript pre-image; pk_hash + domain + version + device_id32 + epoch + reserved fields |
| `T_E` | 274 | 1 336 B | Epoch public key: rho (32 B) + t1 (1 184 B) + epoch (8 B) + device_id16 (16 B) |
| `sig` | 1 610 | 2 420 B | ML-DSA-44 signature over mu = SHAKE256(mu_pre, 64) |

Total Frame v2 length: 4 030 bytes. A frame shorter or longer than this is rejected with
`VerifyError::LengthMismatch` before any transcript check.

### mu_pre fields and binding

- `pk_hash` (bytes 0–63): SHAKE256(T_E, 64) — binds the key to the transcript.
- `domain_sep` (bytes 64–72): `"ANDNAAUTH"` (9 bytes, ASCII).
- `version` (byte 73): `0x01` — wrong value → `MuPreMalformed`.
- `device_id32` (bytes 74–105): SHAKE256(T_E.device_id16, 32).
- `epoch` (bytes 106–113): u64 little-endian, must match T_E.epoch.
- `sid`, `n_d`, `n_s`, `ctx_hash`, `policy_hash` (remaining fields): bound but caller-set;
  ctx_hash meaning is the consumer's responsibility (file-seal sets it to manifest hash).

### Verification order and directives

R1 checks four directives in order; the first failure terminates verification:

1. **pk_hash binding** — recompute SHAKE256(T_E); compare to mu_pre.pk_hash.
   Failure: `PkHashMismatch`.
2. **Epoch correlation** — mu_pre.epoch must equal T_E.epoch.
   Failure: `EpochMismatch`.
3. **Device-id duality** — mu_pre.device_id32 must equal SHAKE256(T_E.device_id16, 32).
   Failure: `DeviceIdMismatch`.
4. **ML-DSA verify** — verify signature over mu = SHAKE256(mu_pre, 64) with T_E's key.
   Failure: `SignatureInvalid`.

Domain separator and version are checked as part of directive 1 (`MuPreMalformed` if wrong).

### Boundary: what R1 does and does not prove

R1 proves a valid ML-DSA-44 signature over the frame's bound transcript contents, including
pk_hash, epoch, device_id32, and the caller-supplied ctx_hash. It does NOT:
- Perform revocation checks — a revoked device's frames still pass R1 if the signature is valid.
- Prove current authorization — that is R2's responsibility.
- Interpret ctx_hash — the file-seal layer enforces that ctx_hash equals the manifest hash;
  R1 does not know the manifest format.

`inspect-seal` reads sidecar structure (frame length, epoch, device fields, manifest hash
binding) and is a valid structural check. It is NOT an authorization decision and cannot
imply ACCEPT.

## Negative-behavior checklist (fed by Branch B characterization tests)

| Scenario | Expected error / outcome | Status |
|---|---|---|
| Frame shorter than 4 030 B | `LengthMismatch` | Covered: `verify_frame_v2_rejects_short` |
| Frame longer than 4 030 B | `LengthMismatch` | Covered by same constant check |
| Wrong domain separator | `MuPreMalformed` | Covered: `verify_vnext_fails_on_bad_domain_sep` |
| Wrong version byte | `MuPreMalformed` | Covered: `verify_vnext_fails_on_bad_version` |
| pk_hash mismatch (T_E byte flip) | `PkHashMismatch` | Covered: multiple tests |
| Epoch mismatch (mu_pre.epoch ≠ T_E.epoch) | `EpochMismatch` | Covered: `rejects_epoch_mismatch` |
| device_id32 mismatch | `DeviceIdMismatch` | Covered: `rejects_device_id_mismatch` |
| Signature byte flip | `SignatureInvalid` | Covered: `rejects_tampered_signature_as_signature_invalid` |
| T_E byte flip | `PkHashMismatch` | Covered: `rejects_tampered_te_as_pk_hash_mismatch` |
| mu_pre byte flip (not pk_hash or domain fields) | signature no longer valid | Covered via pipeline tamper test |
| `inspect-seal` cannot imply ACCEPT | Not a verify result | Branch B adds seal-layer assertion |

All negative directives are covered at the Rust-unit level in `crates/core/src/lib.rs` and
`crates/core/tests/d0_fips204_to_liboqs_r1_interop_accepts.rs`. Branch B adds a seal-layer
assertion: `inspect-seal` structural pass does not produce an ACCEPT verdict.

## Not yet built (future mitigations)

- Signature freshness (timestamp bound on frame age; no clock binding today).
- Short-lived frame tokens tied to an online nonce.
- Multi-frame linkage (preventing a valid old frame from being replayed against a new session
  identifier without R2 revocation awareness).

## Reviewer questions

1. The ctx_hash field is caller-set and zero for frames that do not use the file-seal layer.
   Should the threat doc flag the risk of zero ctx_hash in non-file-seal use cases?
2. Is the ordering guarantee (four directives in sequence, first failure terminates) a
   security property that reviewers should independently verify from the source, or is the
   inline test suite sufficient evidence?
