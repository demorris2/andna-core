# 02 — D0 State Custody and Clone

## Built / true today

All facts below are verified against live source (`crates/andna-d0/src/derive.rs`).

| Constant / symbol | Value | Meaning |
|---|---|---|
| `D0_SPEC_VERSION` | `0x02` | Hash-chain ratchet. `0x01` was the retired byte-additive ratchet. |
| `D0_P_Q` | `8 380 417` | ML-DSA modulus — confirms generation boundary (retired q = 3 329). |
| `D0_HEALING_SLOT_LEN` | `32` | Size of the reserved healing slot. |
| `EPOCH_SEED_DOMAIN` | `"ANDNA-D0-EPOCH-SEED-v1"` | Domain label 1 of 3. |
| `MLDSA_SEED_DOMAIN` | `"ANDNA-D0-MLDSA-SEED-v1"` | Domain label 2 of 3. |
| `RATCHET_STATE_DOMAIN` | `"ANDNA-D0-RATCHET-STATE-v1"` | Domain label 3 of 3. |

**Domain separation: SATISFIED.** Three distinct `-v1`-suffixed SHAKE256 domain labels
separate epoch seed derivation, ML-DSA seed derivation, and ratchet state derivation.
No two derivations share a label. This is a closed check for the current spec version.

**Ratchet construction.** Public entry is `ratchet_deterministic(state, epoch)`, which
internally calls `ratchet_internal(state, epoch, healing = &[0; 32])`. The SHAKE256 input
for the ratchet state is `[RATCHET_STATE_DOMAIN || epoch_le || healing(=0) || state]`.
Security Invariant R-1 (full-state dependence) is coded and commented: the full canonical
state record must be passed as the state input.

**Rejection sampling.** `REJECT_BOUND` enforces mod-bias-free sampling over q = 8 380 417.
Coefficients outside `[0, REJECT_BOUND)` are discarded and resampled.

**Zeroization.** `SecretState` implements `Zeroize`; secret coefficients are zeroed on drop.

## Reserved, inactive mechanism — connected healing

The 32-byte healing slot (`D0_HEALING_SLOT_LEN = 32`) and the feature gate
`d0-connected-healing` both exist in the current code. The internal function
`ratchet_internal(state, epoch, healing)` accepts a healing argument. The public entry
`ratchet_deterministic` always passes all-zero healing.

`check_deterministic_healing(healing)` returns `Err(HealingNonzeroInDeterministicMode)` on
any non-zero healing byte, and this guard is enforced before calling `ratchet_internal`.

**This is a built-but-inactive mechanism, not a missing one.** The slot, the feature gate,
and the deterministic guard all exist. Activation post-review requires specifying the
healing source — a registry-issued epoch nonce, a remote witness checkpoint, or a hardware
co-counter. This is the primary forward-secrecy item for the post-review roadmap.

## Threat analysis

### State extraction

If an adversary can read process memory or the host file system while the sealer is running,
they can obtain the current `SecretState`. Zeroization reduces the window but does not close
it against a root adversary with live memory access.

**Current mitigation:** software zeroization on drop. **Assumed:** the operator's host
controls memory access.

### State cloning

**Core finding, stated plainly:** D0 does not currently prove clone resistance. If the
current state is copied — e.g. a file-system snapshot, a VM clone, a memory image — the
adversary holds an identical state and will produce deterministic future evolution identical
to the legitimate device.

The ratchet supports *prior-state-recovery resistance* under the stated assumption that past
state is not retained: given state at epoch N, computing state at epoch N-1 requires
reversing a SHAKE256 preimage, which is computationally infeasible under standard hash
assumptions. However, if an attacker copies state at epoch N, they have equal standing going
forward until a healing event (which is currently inactive) or revocation.

**Revocation is the only current fallback** against a state-compromised holder.

### State rollback

If an adversary records state at epoch N and later uses it at epoch M < N (by forking the
chain), they can sign frames at epoch M. R2 accepts a frame if the frame's epoch equals the
registry's `current_epoch`. Rollback can be exploited if the registry is also rolled back.

**Current mitigation:** epoch-freshness check in R2 rejects frames whose epoch does not
match `current_epoch`. **Gap:** neither the registry's `current_epoch` nor the snapshot's
`snapshot_seq` is protected by a hardware-rooted monotonic counter.

### Weak or test seed

`SoftwareProfileSigner::from_seed([0x42; 32], ...)` is used extensively in tests. Any
release profile using a constant or low-entropy seed is indistinguishable from a test
fixture at the crypto layer. The demo/MVP sealer generates seed material locally and relies
on the operator to keep the profile file private.

### Secure-deletion assumptions

Software zeroization is the only current protection. It is ineffective against:
- Disk persistence of the profile JSON (seed is not encrypted at rest).
- Memory swap / hibernation.
- VM snapshots that capture heap state before zeroization.

### Hardware-rooting assumptions

D0 makes no hardware guarantees. The spec does not assume a TPM, SGX enclave, SE, or
hardware security module. Hardware rooting is a post-review item.

## Not yet built (future mitigations)

- Hardware monotonic counter (binds ratchet advance to hardware-enforced progress).
- Registry-signed nonce healing (connects epoch advance to an external authority).
- Remote witness checkpoint healing (epoch nonce from an online witness).
- Non-exportable hardware state (TPM / SE custody of secret coefficients).
- Attested enrollment — the trust root for the initial identity (see `09-enrollment-and-provisioning-trust.md`).
- Epoch-velocity policy (limits how fast an epoch can advance, detecting replay).

## Reviewer questions

1. Is the "revocation is the only current fallback" finding stated clearly enough for an
   operator making a deployment decision?
2. Should the healing-source options (registry nonce, remote witness, hardware co-counter)
   be ranked by security strength, or left as equivalents for the reviewer to assess?
