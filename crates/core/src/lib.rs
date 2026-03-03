//! # AN-DNA Core — verify_vnext() orchestrator
//!
//! This crate provides the single public verification entry point.
//! It orchestrates: parse → pk_hash check → compute μ → ML-DSA-44 verify.
//!
//! No logging, no network, no side effects. Pure verification.

#![forbid(unsafe_code)]

use andna_contracts::*;
use andna_transcript::{self, TranscriptError};
use andna_mldsa44::{self, MlDsa44Error};
use zeroize::Zeroize;

// Re-export codec types for convenience
pub use andna_codec::{
    unpack_frame_v2, parse_mu_pre_header, parse_te_meta,
    FrameV2Ref, MuPreHeader, TeMeta, CodecError,
};

/// Unified error type for the verify pipeline.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifyError {
    LengthMismatch,
    MuPreMalformed,
    TeMalformed,
    SigMalformed,
    PkHashMismatch,
    /// Directive B: mu_pre.epoch != T_E.epoch (stale epoch / Frankenstein payload)
    EpochMismatch,
    /// Directive E: device_id32 != SHAKE256(device_id16, 32)
    DeviceIdMismatch,
    SignatureInvalid,
    Internal,
}

impl From<CodecError> for VerifyError {
    fn from(e: CodecError) -> Self {
        match e {
            CodecError::LengthMismatch => VerifyError::LengthMismatch,
            CodecError::MuPreMalformed => VerifyError::MuPreMalformed,
            CodecError::TeMalformed => VerifyError::TeMalformed,
            CodecError::SigMalformed => VerifyError::SigMalformed,
        }
    }
}

impl From<TranscriptError> for VerifyError {
    fn from(e: TranscriptError) -> Self {
        match e {
            TranscriptError::PkHashMismatch => VerifyError::PkHashMismatch,
            TranscriptError::EpochMismatch => VerifyError::EpochMismatch,
            TranscriptError::DeviceIdMismatch => VerifyError::DeviceIdMismatch,
        }
    }
}

impl From<MlDsa44Error> for VerifyError {
    fn from(e: MlDsa44Error) -> Self {
        match e {
            MlDsa44Error::SignatureInvalid => VerifyError::SignatureInvalid,
            MlDsa44Error::PublicKeyMalformed => VerifyError::TeMalformed,
            MlDsa44Error::Internal => VerifyError::Internal,
        }
    }
}

/// Verify an AN-DNA vNext Phase 1 proof given individual components.
///
/// Pipeline:
/// 0. Directive A: Validate mu_pre structure (domain sep "ANDNAAUTH" + version 0x01)
/// 1. Constant-time pk_hash binding check: mu_pre[0..64] == SHAKE256(T_E, 64)
/// 2. Directive B: Epoch correlation: mu_pre.epoch == T_E.epoch
/// 3. Directive E: Device ID duality: mu_pre.device_id32 == SHAKE256(T_E.device_id16, 32)
/// 4. Compute μ = SHAKE256(mu_pre, 64)
/// 5. Extract (ρ, t₁) from T_E
/// 6. ML-DSA-44 verify(ρ, t₁, μ, sig)
/// 7. Zeroize μ
///
/// Returns `Ok(())` on success, `Err(VerifyError)` on any failure.
pub fn verify_vnext(
    mu_pre: &[u8; MU_PRE_LEN],
    te: &[u8; TE_LEN],
    sig: &[u8; SIG_LEN],
) -> Result<(), VerifyError> {
    // Step 0 (Directive A): validate mu_pre structure — domain sep + version
    // Abort before touching lattice math if tampered.
    let _hdr = andna_codec::parse_mu_pre_header(mu_pre)?;

    // Step 1: pk_hash binding (constant-time)
    andna_transcript::check_pk_hash_binding(mu_pre, te)?;

    // Step 2 (Directive B): epoch correlation — reject Frankenstein payloads
    andna_transcript::check_epoch_correlation(mu_pre, te)?;

    // Step 3 (Directive E): device ID duality — SHAKE256(id16) == id32
    andna_transcript::check_device_id_duality(mu_pre, te)?;

    // Step 4: compute μ
    let mut mu = [0u8; MU_LEN];
    andna_transcript::mu_from_mu_pre(mu_pre, &mut mu);

    // Step 5: extract public key parts from T_E
    let (rho, t1) = andna_mldsa44::extract_pubkey_parts(te);

    // Step 6: ML-DSA-44 verify
    let result = andna_mldsa44::verify(rho, t1, &mu, sig);

    // Step 7: zeroize μ regardless of outcome
    mu.zeroize();

    result.map_err(Into::into)
}

/// Verify a packed v2 binary frame (4030 bytes).
///
/// Convenience wrapper: unpack → verify_vnext.
pub fn verify_frame_v2(frame: &[u8]) -> Result<(), VerifyError> {
    let parsed = unpack_frame_v2(frame)?;
    verify_vnext(parsed.mu_pre, parsed.te, parsed.sig)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a mu_pre with correct pk_hash, epoch correlation, and device_id duality
    /// for the given T_E. Satisfies Directives A, B, and E.
    fn make_bound_mu_pre(te: &[u8; TE_LEN]) -> [u8; MU_PRE_LEN] {
        let mut mu_pre = [0u8; MU_PRE_LEN];
        // Compute pk_hash into temp, then copy into mu_pre[0..64]
        let mut pk_hash = [0u8; PK_HASH_LEN];
        andna_transcript::pk_hash_from_te(te, &mut pk_hash);
        mu_pre[0..PK_HASH_LEN].copy_from_slice(&pk_hash);
        // Domain separator (Directive A)
        mu_pre[MU_PRE_DOMAIN_SEP_OFF..MU_PRE_DOMAIN_SEP_OFF + DOMAIN_SEP_LEN]
            .copy_from_slice(&DOMAIN_SEP);
        // Version (Directive A)
        mu_pre[MU_PRE_VERSION_OFF] = MU_PRE_VERSION_VAL;
        // Epoch = copy from T_E (Directive B: must match)
        mu_pre[MU_PRE_EPOCH_OFF..MU_PRE_EPOCH_OFF + MU_PRE_EPOCH_LEN]
            .copy_from_slice(&te[TE_EPOCH_OFF..TE_EPOCH_OFF + TE_EPOCH_LEN]);
        // Device ID = SHAKE256(T_E.device_id16, 32) (Directive E)
        let device_id16: &[u8; TE_DEVICE_ID16_LEN] =
            te[TE_DEVICE_ID16_OFF..TE_DEVICE_ID16_OFF + TE_DEVICE_ID16_LEN]
                .try_into().unwrap();
        let device_id32 = andna_transcript::device_id32_from_id16(device_id16);
        mu_pre[MU_PRE_DEVICE_ID32_OFF..MU_PRE_DEVICE_ID32_OFF + MU_PRE_DEVICE_ID32_LEN]
            .copy_from_slice(&device_id32);
        mu_pre
    }

    /// Build a T_E with specific epoch and device_id16 (for test control).
    fn make_te(epoch: u64, device_id16: &[u8; TE_DEVICE_ID16_LEN]) -> [u8; TE_LEN] {
        let mut te = [0x42u8; TE_LEN];
        te[TE_EPOCH_OFF..TE_EPOCH_OFF + TE_EPOCH_LEN]
            .copy_from_slice(&epoch.to_le_bytes());
        te[TE_DEVICE_ID16_OFF..TE_DEVICE_ID16_OFF + TE_DEVICE_ID16_LEN]
            .copy_from_slice(device_id16);
        te
    }

    // ── Tests that work with any backend ──

    #[test]
    fn verify_vnext_fails_on_pk_hash_mismatch() {
        let te = [0x42u8; TE_LEN];
        let mut mu_pre = [0u8; MU_PRE_LEN]; // wrong pk_hash (all zeros)
        mu_pre[MU_PRE_DOMAIN_SEP_OFF..MU_PRE_DOMAIN_SEP_OFF + DOMAIN_SEP_LEN]
            .copy_from_slice(&DOMAIN_SEP);
        mu_pre[MU_PRE_VERSION_OFF] = MU_PRE_VERSION_VAL;
        let sig = [0u8; SIG_LEN];
        assert_eq!(verify_vnext(&mu_pre, &te, &sig), Err(VerifyError::PkHashMismatch));
    }

    #[test]
    fn verify_vnext_fails_on_bad_domain_sep() {
        // Directive A: tampered domain separator → MuPreMalformed
        let te = make_te(1, &[0xBB; TE_DEVICE_ID16_LEN]);
        let mut mu_pre = make_bound_mu_pre(&te);
        mu_pre[MU_PRE_DOMAIN_SEP_OFF] = 0x00; // corrupt first byte of "ANDNAAUTH"
        let sig = [0u8; SIG_LEN];
        assert_eq!(verify_vnext(&mu_pre, &te, &sig), Err(VerifyError::MuPreMalformed));
    }

    #[test]
    fn verify_vnext_fails_on_bad_version() {
        // Directive A: wrong version byte → MuPreMalformed
        let te = make_te(1, &[0xBB; TE_DEVICE_ID16_LEN]);
        let mut mu_pre = make_bound_mu_pre(&te);
        mu_pre[MU_PRE_VERSION_OFF] = 0xFF;
        let sig = [0u8; SIG_LEN];
        assert_eq!(verify_vnext(&mu_pre, &te, &sig), Err(VerifyError::MuPreMalformed));
    }

    #[test]
    fn verify_vnext_fails_on_epoch_mismatch() {
        // Directive B: mu_pre.epoch != T_E.epoch → EpochMismatch
        let te = make_te(42, &[0xBB; TE_DEVICE_ID16_LEN]);
        let mut mu_pre = make_bound_mu_pre(&te);
        // Tamper epoch in mu_pre to 99 (T_E has 42)
        mu_pre[MU_PRE_EPOCH_OFF..MU_PRE_EPOCH_OFF + MU_PRE_EPOCH_LEN]
            .copy_from_slice(&99u64.to_le_bytes());
        let sig = [0u8; SIG_LEN];
        assert_eq!(verify_vnext(&mu_pre, &te, &sig), Err(VerifyError::EpochMismatch));
    }

    #[test]
    fn verify_vnext_fails_on_device_id_mismatch() {
        // Directive E: device_id32 != SHAKE256(device_id16, 32) → DeviceIdMismatch
        let te = make_te(1, &[0xBB; TE_DEVICE_ID16_LEN]);
        let mut mu_pre = make_bound_mu_pre(&te);
        // Tamper device_id32 (write raw bytes instead of SHAKE256)
        mu_pre[MU_PRE_DEVICE_ID32_OFF..MU_PRE_DEVICE_ID32_OFF + MU_PRE_DEVICE_ID32_LEN]
            .fill(0xCC);
        let sig = [0u8; SIG_LEN];
        assert_eq!(verify_vnext(&mu_pre, &te, &sig), Err(VerifyError::DeviceIdMismatch));
    }

    #[test]
    fn verify_frame_v2_rejects_short() {
        assert_eq!(verify_frame_v2(&[0u8; 100]), Err(VerifyError::LengthMismatch));
    }

    // ── Stub-only tests (zero-filled sig passes with stub) ──

    #[cfg(feature = "stub")]
    #[test]
    fn verify_vnext_pass_with_stub() {
        let te = [0x42u8; TE_LEN];
        let mu_pre = make_bound_mu_pre(&te);
        let sig = [0u8; SIG_LEN];
        assert!(verify_vnext(&mu_pre, &te, &sig).is_ok());
    }

    #[cfg(feature = "stub")]
    #[test]
    fn verify_frame_v2_pass_with_stub() {
        let te = [0x42u8; TE_LEN];
        let mu_pre = make_bound_mu_pre(&te);
        let sig = [0u8; SIG_LEN];

        let mut frame = [0u8; FRAME_V2_LEN];
        andna_codec::pack_frame_v2(&mu_pre, &te, &sig, &mut frame);
        assert!(verify_frame_v2(&frame).is_ok());
    }

    // ── liboqs tests (real keygen → sign → verify through full pipeline) ──

    #[cfg(feature = "oqs-backend")]
    mod oqs_tests {
        use super::*;

        /// Build a real frame: keygen → build T_E → build mu_pre → sign μ → pack.
        fn make_real_frame() -> ([u8; FRAME_V2_LEN], Vec<u8>, Vec<u8>) {
            oqs::init();
            let scheme = oqs::sig::Sig::new(oqs::sig::Algorithm::MlDsa44)
                .expect("ML-DSA-44 not available");

            let (pk, sk) = scheme.keypair().expect("keygen failed");
            let pk_bytes = pk.as_ref();

            // Build T_E from pk components + metadata
            let mut te = [0u8; TE_LEN];
            te[TE_RHO_OFF..TE_RHO_OFF + TE_RHO_LEN]
                .copy_from_slice(&pk_bytes[..TE_RHO_LEN]);
            te[TE_T1_OFF..TE_T1_OFF + TE_T1_LEN]
                .copy_from_slice(&pk_bytes[TE_RHO_LEN..TE_RHO_LEN + TE_T1_LEN]);
            te[TE_EPOCH_OFF..TE_EPOCH_OFF + 8]
                .copy_from_slice(&1u64.to_le_bytes());
            te[TE_DEVICE_ID16_OFF..TE_DEVICE_ID16_OFF + TE_DEVICE_ID16_LEN]
                .copy_from_slice(&[0xCCu8; TE_DEVICE_ID16_LEN]);

            // Build mu_pre with correct pk_hash binding
            let mu_pre = make_bound_mu_pre(&te);

            // Compute μ = SHAKE256(mu_pre, 64)
            let mut mu = [0u8; MU_LEN];
            andna_transcript::mu_from_mu_pre(&mu_pre, &mut mu);

            // Sign μ with real ML-DSA-44
            let signature = scheme.sign(&mu, &sk).expect("sign failed");
            let sig_bytes: &[u8; SIG_LEN] = signature.as_ref()
                .try_into().expect("sig length mismatch");

            // Pack frame
            let mut frame = [0u8; FRAME_V2_LEN];
            andna_codec::pack_frame_v2(&mu_pre, &te, sig_bytes, &mut frame);

            (frame, pk_bytes.to_vec(), sk.as_ref().to_vec())
        }

        #[test]
        fn verify_vnext_real_sig() {
            let (frame, _, _) = make_real_frame();
            assert!(verify_frame_v2(&frame).is_ok(),
                "real ML-DSA-44 sig through full pipeline should pass");
        }

        #[test]
        fn verify_vnext_tampered_sig_rejected() {
            let (mut frame, _, _) = make_real_frame();
            // Tamper the signature (last 2420 bytes of frame)
            let sig_start = MU_PRE_LEN + TE_LEN;
            frame[sig_start] ^= 0xFF;
            assert_eq!(
                verify_frame_v2(&frame),
                Err(VerifyError::SignatureInvalid),
                "tampered signature should be rejected"
            );
        }

        #[test]
        fn verify_vnext_wrong_te_rejected() {
            let (frame, _, _) = make_real_frame();
            // Re-pack with different T_E (breaks pk_hash binding)
            let mut bad_frame = frame;
            bad_frame[MU_PRE_LEN] ^= 0xFF; // flip byte in T_E
            // pk_hash in mu_pre no longer matches, so pk_hash check fails first
            assert_eq!(
                verify_frame_v2(&bad_frame),
                Err(VerifyError::PkHashMismatch),
                "modified T_E should break pk_hash binding"
            );
        }
    }
}
