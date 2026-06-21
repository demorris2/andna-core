//! D0 domain-separation confirm-and-pin — hardening finding F3.
//!
//! Run:
//!   cargo test -p andna-d0 --test d0_domain_separation --locked
//!
//! Confirms and pins: epoch and device_id16 are domain-separated and bound into the
//! SHAKE256 hash (not adjacent unauthenticated metadata), so epoch-confusion and
//! context-confusion fail closed — a substituted epoch or device_id produces a
//! different key and cannot verify against the original binding.
//!
//! Architecture confirmed by source review (derive.rs):
//!   - seed_e(): SHAKE256(EPOCH_SEED_DOMAIN || epoch_record) where epoch_record
//!     includes epoch_le (bytes 8..16) and device_id16 (bytes 16..32) — both INSIDE
//!     the hash input, not metadata.
//!   - ratchet_step(): sample_coeffs_from_parts(&[RATCHET_STATE_DOMAIN, &epoch_le, ...])
//!     — epoch again bound with a distinct domain label.
//!   - Three distinct domain labels: EPOCH_SEED_DOMAIN, MLDSA_SEED_DOMAIN,
//!     RATCHET_STATE_DOMAIN — all confirmed by d0_characterization.rs.
//!
//! RECONCILED against d0_characterization.rs:
//!   - ratchet_output_depends_on_epoch — pins ratchet epoch sensitivity (different
//!     epoch → different ratchet output).
//!
//! This file adds epoch-confusion and context-confusion at the KEY DERIVATION level
//! (derive_epoch_keypair), proving the key itself changes — not just the ratchet
//! intermediate.

use andna_d0::{derive_epoch_keypair, D0Context, SecretState, D0_P_N};

const DEVICE_A: [u8; 16] = [0xAA; 16];
const DEVICE_B: [u8; 16] = [0xBB; 16];

fn test_state() -> SecretState {
    SecretState::from_coeffs([1u32; D0_P_N]).expect("valid state")
}

/// Positive control: same (state, epoch, device_id) produces the same keypair.
/// If this fails, the subsequent differentials are inconclusive.
#[test]
fn positive_control_same_inputs_same_key() {
    let state = test_state();
    let ctx = D0Context {
        epoch: 0,
        device_id16: DEVICE_A,
    };
    let kp1 = derive_epoch_keypair(&state, &ctx).expect("keygen");
    let kp2 = derive_epoch_keypair(&state, &ctx).expect("keygen");
    assert_eq!(
        kp1.public_key_bytes(),
        kp2.public_key_bytes(),
        "positive control: identical inputs must produce identical keys"
    );
}

/// Epoch-confusion: substituting epoch produces a different key. An attacker who
/// replays a frame with a different epoch cannot get the same public key —
/// verification fails closed (pk_hash mismatch at R1 directive 1).
#[test]
fn epoch_substitution_produces_different_key() {
    let state = test_state();
    let ctx0 = D0Context {
        epoch: 0,
        device_id16: DEVICE_A,
    };
    let ctx1 = D0Context {
        epoch: 1,
        device_id16: DEVICE_A,
    };
    let pk0 = derive_epoch_keypair(&state, &ctx0)
        .expect("keygen")
        .public_key_bytes()
        .to_vec();
    let pk1 = derive_epoch_keypair(&state, &ctx1)
        .expect("keygen")
        .public_key_bytes()
        .to_vec();
    assert_ne!(
        pk0, pk1,
        "epoch 0 vs epoch 1 must produce different keys (epoch is bound into the hash)"
    );
}

/// Context-confusion: substituting device_id16 produces a different key. An attacker
/// who substitutes a different device identity cannot get the same public key —
/// verification fails closed.
#[test]
fn device_id_substitution_produces_different_key() {
    let state = test_state();
    let ctx_a = D0Context {
        epoch: 0,
        device_id16: DEVICE_A,
    };
    let ctx_b = D0Context {
        epoch: 0,
        device_id16: DEVICE_B,
    };
    let pk_a = derive_epoch_keypair(&state, &ctx_a)
        .expect("keygen")
        .public_key_bytes()
        .to_vec();
    let pk_b = derive_epoch_keypair(&state, &ctx_b)
        .expect("keygen")
        .public_key_bytes()
        .to_vec();
    assert_ne!(
        pk_a, pk_b,
        "device A vs device B must produce different keys (device_id16 is bound into the hash)"
    );
}

/// Joint confusion: both epoch AND device_id substituted together still produce a
/// different key from the original.
#[test]
fn epoch_and_device_id_joint_substitution_produces_different_key() {
    let state = test_state();
    let original = D0Context {
        epoch: 0,
        device_id16: DEVICE_A,
    };
    let substituted = D0Context {
        epoch: 1,
        device_id16: DEVICE_B,
    };
    let pk_orig = derive_epoch_keypair(&state, &original)
        .expect("keygen")
        .public_key_bytes()
        .to_vec();
    let pk_sub = derive_epoch_keypair(&state, &substituted)
        .expect("keygen")
        .public_key_bytes()
        .to_vec();
    assert_ne!(
        pk_orig, pk_sub,
        "joint epoch+device_id substitution must produce a different key"
    );
}
