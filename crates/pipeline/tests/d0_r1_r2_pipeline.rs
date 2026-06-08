//! End-to-end R1 -> R2 pipeline test (gated on `oqs-backend`).
//!
//! Exercises the R1->R2 seam with a REAL ML-DSA-44 frame generated directly via `fips204`
//! (fixed-seed keypair, structured T_E, bound mu_pre, genuine signature). It deliberately
//! does NOT depend on the D0 crate: the pipeline's job is the R1->R2 orchestration and the
//! fail-closed gate, and the D0->R1 derivation lineage is proven separately by
//! `crates/core/tests/d0_fips204_to_liboqs_r1_interop_accepts.rs`. Filename kept for continuity.
//!
//! Asserts the combined decision end to end:
//!   * authorizing registry  -> R1 ACCEPT -> R2 AUTHORIZED      (registry_entry_valid)
//!   * unknown device         -> R1 ACCEPT -> R2 NOT_AUTHORIZED  (no_registry_entry)
//!   * tampered signature     -> R1 REJECT -> R2 NOT_EVALUATED   (stage1_reject)   [fail-closed]
//!
//! Run:
//!   cargo test -p andna-pipeline --test d0_r1_r2_pipeline -- --nocapture

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

const PK_E_LEN: usize = TE_RHO_LEN + TE_T1_LEN; // 1312 = rho || t1
const TEST_EPOCH: u64 = 0;
const TEST_DEVICE_ID16: [u8; TE_DEVICE_ID16_LEN] = [0xD0; TE_DEVICE_ID16_LEN];
const TEST_SEED: [u8; 32] = [0x42; 32];

// ── tests ─────────────────────────────────────────────────────────────────────

#[test]
fn authorized_end_to_end() {
    let frame = build_valid_frame();
    let facts = verified_facts_from_accepted_frame(&frame).expect("facts");
    let reg = registry_authorizing(&facts);

    let d = verify_and_authorize(&frame, &reg);

    assert!(d.r1.accepted);
    assert_eq!(d.r1.verify_error, None);
    assert_eq!(d.r2.stage1, "CRYPTO_ACCEPT");
    assert_eq!(d.r2.stage2, "AUTHORIZED");
    assert_eq!(d.r2.reason, "registry_entry_valid");
    assert_eq!(d.r2.attestation_status, "NONE_SOFTWARE_PROFILE");
    let policy_digest =
        d.r2.policy_digest_hex
            .as_deref()
            .expect("AUTHORIZED decision must carry a policy_digest");
    assert_eq!(policy_digest.len(), 64); // 32-byte SHA3-256 as hex
                                         // Frame hash and policy digest are distinct artifacts.
    assert_eq!(d.r1.frame_hash_hex.len(), 64);
    assert_ne!(d.r1.frame_hash_hex.as_str(), policy_digest);
}

#[test]
fn not_authorized_when_device_unknown() {
    let frame = build_valid_frame();
    let reg = registry_empty();

    let d = verify_and_authorize(&frame, &reg);

    assert!(d.r1.accepted); // the crypto is fine
    assert_eq!(d.r2.stage1, "CRYPTO_ACCEPT");
    assert_eq!(d.r2.stage2, "NOT_AUTHORIZED");
    assert_eq!(d.r2.reason, "no_registry_entry");
}

#[test]
fn not_evaluated_when_signature_tampered_even_if_registry_would_authorize() {
    // Authorizing registry built from the CLEAN frame's facts...
    let clean = build_valid_frame();
    let facts = verified_facts_from_accepted_frame(&clean).expect("facts");
    let reg = registry_authorizing(&facts);

    // ...then tamper the signature so R1 must reject.
    let mut frame = build_valid_frame();
    frame[FRAME_V2_SIG_OFF] ^= 0xFF;

    let d = verify_and_authorize(&frame, &reg);

    // Fail-closed: a registry that would authorize this device cannot rescue a bad signature.
    assert!(!d.r1.accepted);
    assert_eq!(d.r1.verify_error.as_deref(), Some("signature_invalid"));
    assert_eq!(d.r2.stage1, "CRYPTO_REJECT");
    assert_eq!(d.r2.stage2, "NOT_EVALUATED");
    assert_eq!(d.r2.reason, "stage1_reject");
}

#[test]
fn combined_decision_serializes_to_json() {
    let frame = build_valid_frame();
    let facts = verified_facts_from_accepted_frame(&frame).expect("facts");
    let reg = registry_authorizing(&facts);

    let json = verify_and_authorize(&frame, &reg).to_json_pretty();
    assert!(json.contains("\"stage2\": \"AUTHORIZED\""));
    assert!(json.contains("\"frame_hash_hex\""));
    assert!(json.contains("\"policy_digest_hex\""));
}

// ── self-contained frame construction (real ML-DSA-44 via fips204) ────────────

/// Deterministic ML-DSA-44 keypair from a fixed seed. Mirrors the fips204 0.4.6 API the
/// D0 bridge uses: `KG::keygen_from_seed(&[u8;32]) -> (PublicKey, PrivateKey)`,
/// `pk.into_bytes()` -> 1312-byte (rho || t1) public key.
fn keypair() -> ([u8; PK_E_LEN], PrivateKey) {
    let (pk, sk) = KG::keygen_from_seed(&TEST_SEED);
    let pk_full = pk.into_bytes();
    assert_eq!(
        pk_full.len(),
        PK_E_LEN,
        "ML-DSA-44 pk must be {PK_E_LEN} bytes"
    );
    let mut pk_arr = [0u8; PK_E_LEN];
    pk_arr.copy_from_slice(&pk_full);
    (pk_arr, sk)
}

/// `T_E = pk(rho||t1) || u64le(epoch) || device_id16`, at the shared contract offsets.
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

/// Fully-correct mu_pre bound to `te` (pk_hash, domain, version, epoch, device_id32) using
/// R1's own transcript helpers.
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

/// Build a valid Frame v2: sign mu = SHAKE256(mu_pre, 64) (empty ctx) and pack
/// mu_pre || T_E || sig.
fn build_valid_frame() -> [u8; FRAME_V2_LEN] {
    let (pk, sk) = keypair();
    let te = build_t_e(&pk, TEST_EPOCH, &TEST_DEVICE_ID16);
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

// ── registry fixtures (built from the frame's own R1-confirmed facts) ───────────

fn registry_authorizing(facts: &VerifiedFacts) -> Registry {
    Registry {
        snapshot_seq: 1,
        as_of_unix_ms: 1_700_000_000_000,
        policy_version: "e2e-registry-v0".to_string(),
        entries: vec![RegistryEntry {
            device_id16: facts.device_id16,
            device_id32: facts.device_id32,
            authorized_te_hashes: vec![facts.te_hash],
            current_epoch: facts.epoch,
            revoked: false,
            frozen: false,
            recovery_hold: false,
            policy_version: "e2e-device-v0".to_string(),
        }],
    }
}

fn registry_empty() -> Registry {
    Registry {
        snapshot_seq: 1,
        as_of_unix_ms: 1_700_000_000_000,
        policy_version: "e2e-registry-v0".to_string(),
        entries: vec![],
    }
}
