//! d0_fips204_to_liboqs_r1_interop_accepts
//!
//! STATUS — D0 -> R1 cross-backend interop: PASSING across epochs 0/1/2 and falsifiable
//! across all four verifier directives, against the real liboqs verifier. Bounded to the
//! fixed D0 test fixture lineage and these paths; NOT a claim of R2 authorization,
//! hardware attestation, multi-device lineage, or production D0 security.
//!
//! END-TO-END D0 -> R1 interop gate. Lives in `crates/core/tests/`; build/run only with
//! the real verifier backend:
//!     cargo test -p andna-core --locked --features oqs-backend \
//!         --test d0_fips204_to_liboqs_r1_interop_accepts -- --nocapture
//! (gated via `required-features = ["oqs-backend"]` in crates/core/Cargo.toml).
//!
//! POSITIVE (proves the bridge is structural, not a one-vector accident):
//!   epoch 0, 1, 2 — each derived along the real ratchet lineage P_0 -> P_1 -> P_2 —
//!   builds a D0-derived frame that ACCEPTs through `andna_core::verify_frame_v2`.
//!
//! NEGATIVE (proves each verifier directive independently, by exact error variant).
//! verify_vnext checks in this order: pk_hash -> epoch -> device-id -> ML-DSA verify.
//!   PkHashMismatch   — flip a T_E byte; recomputed SHAKE256(T_E) != mu_pre.pk_hash (step 1).
//!   EpochMismatch    — mu_pre.epoch != T_E.epoch, all else valid incl. signature (step 2).
//!   DeviceIdMismatch — mu_pre.device_id32 wrong, all else valid incl. signature (step 3).
//!   SignatureInvalid — valid mu_pre/T_E, corrupted signature; fails at ML-DSA verify (step 4).
//!
//! The two transcript-directive negatives (EpochMismatch, DeviceIdMismatch) are built as
//! internally-consistent frames — pk_hash correct and the signature valid over the
//! altered mu_pre — so the ONLY violated directive is the target one. They are not
//! casual byte flips, which could trip an earlier check and fail for the wrong reason.
//!
//! R1 is the FIXED boundary: this test calls R1's real helpers and `verify_frame_v2`,
//! never a reimplementation. If a case fails, the fix goes in the D0 / T_E / mu_pre
//! construction here — never the verifier.

use andna_contracts::{
    DOMAIN_SEP, DOMAIN_SEP_LEN, FRAME_V2_LEN, FRAME_V2_MU_PRE_OFF, FRAME_V2_SIG_OFF,
    FRAME_V2_TE_OFF, MU_LEN, MU_PRE_DEVICE_ID32_LEN, MU_PRE_DEVICE_ID32_OFF, MU_PRE_DOMAIN_SEP_OFF,
    MU_PRE_EPOCH_LEN, MU_PRE_EPOCH_OFF, MU_PRE_LEN, MU_PRE_PK_HASH_OFF, MU_PRE_VERSION_OFF,
    MU_PRE_VERSION_VAL, PK_HASH_LEN, SIG_LEN, TE_DEVICE_ID16_LEN, TE_DEVICE_ID16_OFF, TE_EPOCH_LEN,
    TE_EPOCH_OFF, TE_LEN,
};
use andna_core::{verify_frame_v2, VerifyError};
use andna_d0::test_vectors::{p0_test_fixture, test_device_id16};
use andna_d0::{
    build_t_e, derive_epoch_keypair, ratchet_deterministic, D0Context, EpochKeypair, SecretState,
};
use fips204::traits::Signer;

// ── positive: ACCEPT across the real ratchet lineage ─────────────────────────

/// epochs 0, 1, 2 each build a D0-derived frame that the unmodified liboqs R1 verifier
/// accepts. Each epoch's key is derived from the correctly-ratcheted state, proving the
/// keygen/T_E/mu_pre/verify chain holds as both the secret state and the epoch field vary.
#[test]
fn accepts_epochs_0_1_2() {
    let device_id16 = test_device_id16();
    for epoch in [0u64, 1, 2] {
        let (kp, te) = epoch_keypair_and_te(epoch, &device_id16);
        let mu_pre = build_bound_mu_pre(&te);
        let frame = frame_from(&kp, &te, &mu_pre);
        let decision = verify_frame_v2(&frame);
        assert!(
            decision.is_ok(),
            "epoch {epoch}: D0-derived frame must ACCEPT through the liboqs R1 verifier, \
             got {decision:?}. Fix the D0 / T_E / mu_pre construction here, never the verifier."
        );
    }
}

// ── negative: each directive isolated, asserted by exact variant ─────────────

/// Directive 1 (pk_hash binding): a single flipped T_E byte makes
/// SHAKE256(T_E) != mu_pre.pk_hash. This is the first check, so a byte flip is exact.
#[test]
fn rejects_tampered_te_as_pk_hash_mismatch() {
    let device_id16 = test_device_id16();
    let (kp, te) = epoch_keypair_and_te(0, &device_id16);
    let mu_pre = build_bound_mu_pre(&te);
    let mut frame = frame_from(&kp, &te, &mu_pre);
    frame[FRAME_V2_TE_OFF] ^= 0xFF; // flip rho[0] inside the framed T_E
    assert_eq!(verify_frame_v2(&frame), Err(VerifyError::PkHashMismatch));
}

/// Directive 2 (epoch correlation): mu_pre.epoch != T_E.epoch, with pk_hash, device-id,
/// and the signature all valid over the altered mu_pre — only epoch is wrong.
#[test]
fn rejects_epoch_mismatch() {
    let device_id16 = test_device_id16();
    let (kp, te) = epoch_keypair_and_te(0, &device_id16); // T_E.epoch == 0
    let mut mu_pre = build_bound_mu_pre(&te); // correct pk_hash + device_id32 + epoch 0
    mu_pre[MU_PRE_EPOCH_OFF..MU_PRE_EPOCH_OFF + MU_PRE_EPOCH_LEN]
        .copy_from_slice(&1u64.to_le_bytes()); // claim epoch 1 != T_E.epoch (0)
    let frame = frame_from(&kp, &te, &mu_pre); // signature valid over THIS mu_pre
    assert_eq!(verify_frame_v2(&frame), Err(VerifyError::EpochMismatch));
}

/// Directive 3 (device-id duality): mu_pre.device_id32 != SHAKE256(T_E.device_id16, 32),
/// with pk_hash, epoch, and the signature all valid — only device-id is wrong.
#[test]
fn rejects_device_id_mismatch() {
    let device_id16 = test_device_id16();
    let (kp, te) = epoch_keypair_and_te(0, &device_id16);
    let mut mu_pre = build_bound_mu_pre(&te); // correct pk_hash + epoch + device_id32
    let wrong_id32 = [0xFFu8; MU_PRE_DEVICE_ID32_LEN]; // not SHAKE256(device_id16, 32)
    mu_pre[MU_PRE_DEVICE_ID32_OFF..MU_PRE_DEVICE_ID32_OFF + MU_PRE_DEVICE_ID32_LEN]
        .copy_from_slice(&wrong_id32);
    let frame = frame_from(&kp, &te, &mu_pre); // signature valid over THIS mu_pre
    assert_eq!(verify_frame_v2(&frame), Err(VerifyError::DeviceIdMismatch));
}

/// Directive 4 (ML-DSA verify): valid mu_pre and T_E, corrupted signature; the verifier
/// reaches the lattice verification and rejects there.
#[test]
fn rejects_tampered_signature_as_signature_invalid() {
    let device_id16 = test_device_id16();
    let (kp, te) = epoch_keypair_and_te(0, &device_id16);
    let mu_pre = build_bound_mu_pre(&te);
    let mut frame = frame_from(&kp, &te, &mu_pre);
    frame[FRAME_V2_SIG_OFF] ^= 0xFF; // flip first byte of the signature region
    assert_eq!(verify_frame_v2(&frame), Err(VerifyError::SignatureInvalid));
}

// ── helpers ──────────────────────────────────────────────────────────────────

/// Ratchet the fixed test fixture P_0 forward to the secret state for `epoch`:
/// P_0, then P_{e+1} = ratchet_deterministic(P_e, e). Matches the D0 §14 KAT lineage.
fn epoch_state(epoch: u64) -> SecretState {
    let mut s = p0_test_fixture();
    for e in 0..epoch {
        s = ratchet_deterministic(&s, e);
    }
    s
}

/// Derive the D0 epoch keypair for `epoch` (along the ratchet lineage) and its T_E.
fn epoch_keypair_and_te(
    epoch: u64,
    device_id16: &[u8; TE_DEVICE_ID16_LEN],
) -> (EpochKeypair, [u8; TE_LEN]) {
    let state = epoch_state(epoch);
    let ctx = D0Context {
        epoch,
        device_id16: *device_id16,
    };
    let kp = derive_epoch_keypair(&state, &ctx).expect("derive_epoch_keypair");
    let te = build_t_e(kp.public_key_bytes(), epoch, device_id16);
    (kp, te)
}

/// Sign mu = SHAKE256(mu_pre, 64) with the epoch key and pack mu_pre || T_E || sig.
/// The signature is ALWAYS valid over the supplied mu_pre — so when a frame is rejected
/// it is rejected by a transcript directive, never by an incidental signature break.
fn frame_from(
    kp: &EpochKeypair,
    te: &[u8; TE_LEN],
    mu_pre: &[u8; MU_PRE_LEN],
) -> [u8; FRAME_V2_LEN] {
    let mut mu = [0u8; MU_LEN];
    andna_transcript::mu_from_mu_pre(mu_pre, &mut mu);
    let sig: [u8; SIG_LEN] = kp
        .private_key()
        .try_sign(&mu, &[])
        .expect("fips204 ML-DSA-44 sign over mu");
    let mut frame = [0u8; FRAME_V2_LEN];
    frame[FRAME_V2_MU_PRE_OFF..FRAME_V2_MU_PRE_OFF + MU_PRE_LEN].copy_from_slice(mu_pre);
    frame[FRAME_V2_TE_OFF..FRAME_V2_TE_OFF + TE_LEN].copy_from_slice(te);
    frame[FRAME_V2_SIG_OFF..FRAME_V2_SIG_OFF + SIG_LEN].copy_from_slice(&sig);
    frame
}

/// Build a fully-correct `mu_pre` bound to `te` (the four checked directives all pass):
///   pk_hash  = SHAKE256(T_E, 64)                       (binding)
///   domain   = "ANDNAAUTH" + version 0x01              (header)
///   epoch    = T_E.epoch                               (Directive B)
///   id32     = SHAKE256(T_E.device_id16, 32)           (Directive E)
/// Unchecked fields (sid, n_d, n_s, ctx_hash, policy_hash) stay zero. Uses R1's own
/// transcript helpers + shared contract offsets — the D0 side adapting to R1, not a
/// shadow verifier.
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
        .expect("device_id16 slice width");
    let id32 = andna_transcript::device_id32_from_id16(id16);
    mu_pre[MU_PRE_DEVICE_ID32_OFF..MU_PRE_DEVICE_ID32_OFF + MU_PRE_DEVICE_ID32_LEN]
        .copy_from_slice(&id32);

    mu_pre
}
