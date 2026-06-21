//! R1→R2 value-binding differential — hardening finding F5.
//!
//! Run:
//!   cargo test -p andna-pipeline --test r1_r2_value_binding -- --nocapture
//!
//! Proves the frame R1 ACCEPTS is the EXACT frame whose identity R2 evaluates — value
//! identity at the seam, not just that the calls are connected. Complements the existing
//! `not_evaluated_when_signature_tampered_even_if_registry_would_authorize` (the fail-closed
//! half) with the positive-binding half.
//!
//! Method: construct TWO distinct valid frames from different keys. Both pass R1 (signature
//! valid). Build a registry that authorizes ONLY frame_a's identity. Assert:
//!   - frame_a + reg_a → AUTHORIZED (positive control: the right frame is accepted)
//!   - frame_b + reg_a → R1 ACCEPT, R2 NOT_AUTHORIZED (R2 sees frame_b's identity, not a's)
//!
//! This is the "wired ≠ value-bound" test: if the pipeline were syntactically wired but
//! NOT value-bound (e.g. it always extracted facts from some default or cached frame), both
//! frames would authorize. The differential catches that.
//!
//! RECONCILED against d0_r1_r2_pipeline.rs:
//!   - authorized_end_to_end — single-frame positive path
//!   - not_authorized_when_device_unknown — empty registry
//!   - not_evaluated_when_signature_tampered — fail-closed half (R1 reject → R2 NOT_EVALUATED)

use andna_contracts::{
    DOMAIN_SEP, DOMAIN_SEP_LEN, FRAME_V2_LEN, FRAME_V2_MU_PRE_OFF, FRAME_V2_SIG_OFF,
    FRAME_V2_TE_OFF, MU_LEN, MU_PRE_DEVICE_ID32_LEN, MU_PRE_DEVICE_ID32_OFF, MU_PRE_DOMAIN_SEP_OFF,
    MU_PRE_EPOCH_LEN, MU_PRE_EPOCH_OFF, MU_PRE_LEN, MU_PRE_PK_HASH_OFF, MU_PRE_VERSION_OFF,
    MU_PRE_VERSION_VAL, PK_HASH_LEN, SIG_LEN, TE_DEVICE_ID16_LEN, TE_DEVICE_ID16_OFF, TE_EPOCH_LEN,
    TE_EPOCH_OFF, TE_LEN, TE_RHO_LEN, TE_T1_LEN,
};
use andna_pipeline::{
    verified_facts_from_accepted_frame, verify_and_authorize, Registry, RegistryEntry,
    VerifiedFacts,
};
use fips204::ml_dsa_44::{PrivateKey, KG};
use fips204::traits::{KeyGen, SerDes, Signer};

const PK_E_LEN: usize = TE_RHO_LEN + TE_T1_LEN;
const EPOCH: u64 = 0;
const DEVICE_A: [u8; TE_DEVICE_ID16_LEN] = [0xAA; TE_DEVICE_ID16_LEN];
const DEVICE_B: [u8; TE_DEVICE_ID16_LEN] = [0xBB; TE_DEVICE_ID16_LEN];
const SEED_A: [u8; 32] = [0x42; 32];
const SEED_B: [u8; 32] = [0x77; 32];

/// Positive control: two distinct frames, registry authorizes frame_a. Frame_a gets
/// AUTHORIZED; frame_b gets R1 ACCEPT but R2 NOT_AUTHORIZED.
///
/// If the pipeline were NOT value-bound (e.g. it cached facts from the last call, or
/// extracted from a default frame), both would authorize. This test catches that.
#[test]
fn r2_evaluates_the_exact_frame_r1_accepted() {
    let frame_a = build_frame(&SEED_A, &DEVICE_A, EPOCH);
    let frame_b = build_frame(&SEED_B, &DEVICE_B, EPOCH);

    let facts_a = verified_facts_from_accepted_frame(&frame_a).expect("facts_a");
    let facts_b = verified_facts_from_accepted_frame(&frame_b).expect("facts_b");

    assert_ne!(
        facts_a.device_id16, facts_b.device_id16,
        "setup: two frames must have different device identities"
    );
    assert_ne!(
        facts_a.te_hash, facts_b.te_hash,
        "setup: two frames must have different te_hashes (different keys)"
    );

    let reg_a = registry_authorizing(&facts_a);

    let d_a = verify_and_authorize(&frame_a, &reg_a);
    assert!(d_a.r1.accepted, "frame_a: R1 must accept");
    assert_eq!(
        d_a.r2.stage2, "AUTHORIZED",
        "frame_a: R2 must authorize (registry matches)"
    );

    let d_b = verify_and_authorize(&frame_b, &reg_a);
    assert!(
        d_b.r1.accepted,
        "frame_b: R1 must accept (valid signature, just different identity)"
    );
    assert_eq!(
        d_b.r2.stage2, "NOT_AUTHORIZED",
        "frame_b: R2 must NOT authorize — it must evaluate frame_b's identity \
         (not frame_a's), and the registry only authorizes frame_a"
    );
    assert_eq!(d_b.r2.reason, "no_registry_entry");
}

/// Stronger differential: same key, different device_id. Proves the value-binding
/// goes through device identity, not just "was some frame accepted."
#[test]
fn r2_distinguishes_same_key_different_device() {
    let frame_a = build_frame(&SEED_A, &DEVICE_A, EPOCH);
    let frame_b = build_frame(&SEED_A, &DEVICE_B, EPOCH);

    let facts_a = verified_facts_from_accepted_frame(&frame_a).expect("facts_a");

    assert_eq!(
        facts_a.device_id16, DEVICE_A,
        "setup: frame_a must carry device_id A"
    );

    let reg_a = registry_authorizing(&facts_a);

    let d_a = verify_and_authorize(&frame_a, &reg_a);
    assert_eq!(d_a.r2.stage2, "AUTHORIZED");

    let d_b = verify_and_authorize(&frame_b, &reg_a);
    assert!(d_b.r1.accepted, "frame_b: R1 accepts (same key, valid sig)");
    assert_eq!(
        d_b.r2.stage2, "NOT_AUTHORIZED",
        "frame_b: R2 must reject because device_id B is not in the registry"
    );
}

fn keypair(seed: &[u8; 32]) -> ([u8; PK_E_LEN], PrivateKey) {
    let (pk, sk) = KG::keygen_from_seed(seed);
    let pk_full = pk.into_bytes();
    let mut pk_arr = [0u8; PK_E_LEN];
    pk_arr.copy_from_slice(&pk_full);
    (pk_arr, sk)
}

fn build_t_e(
    pk: &[u8; PK_E_LEN],
    epoch: u64,
    device_id16: &[u8; TE_DEVICE_ID16_LEN],
) -> [u8; TE_LEN] {
    let mut te = [0u8; TE_LEN];
    te[..PK_E_LEN].copy_from_slice(pk);
    te[TE_EPOCH_OFF..TE_EPOCH_OFF + TE_EPOCH_LEN].copy_from_slice(&epoch.to_le_bytes());
    te[TE_DEVICE_ID16_OFF..TE_DEVICE_ID16_OFF + TE_DEVICE_ID16_LEN].copy_from_slice(device_id16);
    te
}

fn build_bound_mu_pre(te: &[u8; TE_LEN]) -> [u8; MU_PRE_LEN] {
    let mut mu_pre = [0u8; MU_PRE_LEN];
    let mut pk_hash = [0u8; PK_HASH_LEN];
    andna_transcript::pk_hash_from_te(te, &mut pk_hash);
    mu_pre[MU_PRE_PK_HASH_OFF..MU_PRE_PK_HASH_OFF + PK_HASH_LEN].copy_from_slice(&pk_hash);
    mu_pre[MU_PRE_DOMAIN_SEP_OFF..MU_PRE_DOMAIN_SEP_OFF + DOMAIN_SEP_LEN]
        .copy_from_slice(&DOMAIN_SEP);
    mu_pre[MU_PRE_VERSION_OFF] = MU_PRE_VERSION_VAL;
    mu_pre[MU_PRE_EPOCH_OFF..MU_PRE_EPOCH_OFF + MU_PRE_EPOCH_LEN]
        .copy_from_slice(&te[TE_EPOCH_OFF..TE_EPOCH_OFF + TE_EPOCH_LEN]);
    let id16: &[u8; TE_DEVICE_ID16_LEN] = te
        [TE_DEVICE_ID16_OFF..TE_DEVICE_ID16_OFF + TE_DEVICE_ID16_LEN]
        .try_into()
        .expect("device_id16 width");
    let id32 = andna_transcript::device_id32_from_id16(id16);
    mu_pre[MU_PRE_DEVICE_ID32_OFF..MU_PRE_DEVICE_ID32_OFF + MU_PRE_DEVICE_ID32_LEN]
        .copy_from_slice(&id32);
    mu_pre
}

fn build_frame(
    seed: &[u8; 32],
    device_id16: &[u8; TE_DEVICE_ID16_LEN],
    epoch: u64,
) -> [u8; FRAME_V2_LEN] {
    let (pk, sk) = keypair(seed);
    let te = build_t_e(&pk, epoch, device_id16);
    let mu_pre = build_bound_mu_pre(&te);
    let mut mu = [0u8; MU_LEN];
    andna_transcript::mu_from_mu_pre(&mu_pre, &mut mu);
    let sig: [u8; SIG_LEN] = sk.try_sign(&mu, &[]).expect("fips204 sign");
    let mut frame = [0u8; FRAME_V2_LEN];
    frame[FRAME_V2_MU_PRE_OFF..FRAME_V2_MU_PRE_OFF + MU_PRE_LEN].copy_from_slice(&mu_pre);
    frame[FRAME_V2_TE_OFF..FRAME_V2_TE_OFF + TE_LEN].copy_from_slice(&te);
    frame[FRAME_V2_SIG_OFF..FRAME_V2_SIG_OFF + SIG_LEN].copy_from_slice(&sig);
    frame
}

fn registry_authorizing(facts: &VerifiedFacts) -> Registry {
    Registry {
        snapshot_seq: 1,
        as_of_unix_ms: 1_700_000_000_000,
        policy_version: "value-binding-registry-v0".to_string(),
        entries: vec![RegistryEntry {
            device_id16: facts.device_id16,
            device_id32: facts.device_id32,
            authorized_te_hashes: vec![facts.te_hash],
            current_epoch: facts.epoch,
            revoked: false,
            frozen: false,
            recovery_hold: false,
            policy_version: "value-binding-device-v0".to_string(),
        }],
    }
}
