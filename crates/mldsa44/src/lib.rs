//! # AN-DNA ML-DSA-44 Verification Engine
//!
//! This crate wraps ML-DSA-44 (FIPS 204) signature verification via liboqs.
//!
//! ## Features
//!
//! - `oqs-backend` (**default**): Real ML-DSA-44 verify via liboqs.
//! - `stub`: Always-pass stub for environments without liboqs.
//!   Use: `cargo test -p andna-mldsa44 --no-default-features --features stub`
//!
//! ## Interface
//!
//! Two entry points:
//! - `verify(rho, t1, mu, sig)` — AN-DNA pipeline interface (mu = SHAKE256(mu_pre, 64))
//! - `verify_pk(pk, message, sig)` — Direct liboqs interface for ACVP testing
//!
//! The prover signs M = μ using standard ML-DSA.Sign(sk, M=μ).
//! The verifier calls ML-DSA.Verify(pk, M=μ, σ) via liboqs.

#![forbid(unsafe_code)]

use andna_contracts::*;

/// ML-DSA-44 public key length: ρ(32) + t₁(1280) = 1312 bytes.
pub const ML_DSA_44_PK_LEN: usize = TE_RHO_LEN + TE_T1_LEN; // 1312

/// ML-DSA-44 verification error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MlDsa44Error {
    /// Signature verification failed (reject).
    SignatureInvalid,
    /// Public key encoding is malformed.
    PublicKeyMalformed,
    /// Internal engine error (liboqs init failure, etc.).
    Internal,
}

impl core::fmt::Display for MlDsa44Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::SignatureInvalid => write!(f, "ML-DSA-44 signature verification failed"),
            Self::PublicKeyMalformed => write!(f, "ML-DSA-44 public key malformed"),
            Self::Internal => write!(f, "ML-DSA-44 internal engine error"),
        }
    }
}

// ============================================================================
// liboqs Backend (default feature: oqs-backend)
// ============================================================================

#[cfg(feature = "oqs-backend")]
mod backend {
    use super::*;
    use std::sync::Once;

    static OQS_INIT: Once = Once::new();

    /// Ensure liboqs is initialized exactly once per process.
    fn ensure_init() {
        OQS_INIT.call_once(|| {
            oqs::init();
        });
    }

    /// Verify an ML-DSA-44 signature using the packed public key.
    pub fn verify_pk(pk: &[u8], message: &[u8], sig: &[u8]) -> Result<(), MlDsa44Error> {
        ensure_init();

        let scheme =
            oqs::sig::Sig::new(oqs::sig::Algorithm::MlDsa44).map_err(|_| MlDsa44Error::Internal)?;

        if pk.len() != scheme.length_public_key() {
            return Err(MlDsa44Error::PublicKeyMalformed);
        }
        if sig.len() != scheme.length_signature() {
            return Err(MlDsa44Error::SignatureInvalid);
        }

        let pk_ref = scheme
            .public_key_from_bytes(pk)
            .ok_or(MlDsa44Error::PublicKeyMalformed)?;
        let sig_ref = scheme
            .signature_from_bytes(sig)
            .ok_or(MlDsa44Error::SignatureInvalid)?;

        scheme
            .verify(message, sig_ref, pk_ref)
            .map_err(|_| MlDsa44Error::SignatureInvalid)
    }
}

// ============================================================================
// Stub Backend (feature: stub, for environments without liboqs)
// ============================================================================

#[cfg(all(feature = "stub", not(feature = "oqs-backend")))]
mod backend {
    use super::*;

    /// Stub: always passes. For CI/testing environments without liboqs.
    pub fn verify_pk(pk: &[u8], message: &[u8], sig: &[u8]) -> Result<(), MlDsa44Error> {
        if pk.len() != ML_DSA_44_PK_LEN {
            return Err(MlDsa44Error::PublicKeyMalformed);
        }
        if sig.len() != SIG_LEN {
            return Err(MlDsa44Error::SignatureInvalid);
        }
        let _ = message;
        Ok(())
    }
}

// ============================================================================
// Compile-time gate: exactly one backend must be active
// ============================================================================

#[cfg(not(any(feature = "oqs-backend", feature = "stub")))]
compile_error!(
    "andna-mldsa44: enable either `oqs-backend` (default) or `stub` feature. \
     Example: cargo build -p andna-mldsa44 --features stub"
);

// ============================================================================
// Public API
// ============================================================================

/// Verify an ML-DSA-44 signature using the packed public key and
/// arbitrary-length message. This is the ACVP-testable entry point.
pub fn verify_pk(pk: &[u8], message: &[u8], sig: &[u8]) -> Result<(), MlDsa44Error> {
    backend::verify_pk(pk, message, sig)
}

/// Verify an ML-DSA-44 signature over message μ using the public key
/// components extracted from T_E.
///
/// This is the AN-DNA pipeline interface. The core orchestrator calls this.
///
/// Internally reconstructs pk = ρ || t₁ and calls `verify_pk(pk, μ, sig)`.
pub fn verify(
    rho: &[u8; TE_RHO_LEN],
    t1: &[u8; TE_T1_LEN],
    mu: &[u8; MU_LEN],
    sig: &[u8; SIG_LEN],
) -> Result<(), MlDsa44Error> {
    let mut pk = [0u8; ML_DSA_44_PK_LEN];
    pk[..TE_RHO_LEN].copy_from_slice(rho);
    pk[TE_RHO_LEN..].copy_from_slice(t1);

    verify_pk(&pk, mu, sig)
}

/// Helper: extract (ρ, t₁) from a T_E byte array.
pub fn extract_pubkey_parts(te: &[u8; TE_LEN]) -> (&[u8; TE_RHO_LEN], &[u8; TE_T1_LEN]) {
    let rho: &[u8; TE_RHO_LEN] = te[TE_RHO_OFF..TE_RHO_OFF + TE_RHO_LEN]
        .try_into()
        .expect("compile-time size guarantees this");
    let t1: &[u8; TE_T1_LEN] = te[TE_T1_OFF..TE_T1_OFF + TE_T1_LEN]
        .try_into()
        .expect("compile-time size guarantees this");
    (rho, t1)
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_pubkey_parts_offsets() {
        let mut te = [0u8; TE_LEN];
        te[0] = 0xAA;
        te[TE_T1_OFF] = 0xBB;
        let (rho, t1) = extract_pubkey_parts(&te);
        assert_eq!(rho[0], 0xAA);
        assert_eq!(t1[0], 0xBB);
    }

    #[test]
    fn pk_len_matches_contracts() {
        assert_eq!(ML_DSA_44_PK_LEN, 1312);
        assert_eq!(ML_DSA_44_PK_LEN, TE_RHO_LEN + TE_T1_LEN);
    }

    #[test]
    fn verify_rejects_wrong_pk_len() {
        let short_pk = [0u8; 100];
        let sig = [0u8; SIG_LEN];
        assert_eq!(
            verify_pk(&short_pk, &[0u8; 64], &sig),
            Err(MlDsa44Error::PublicKeyMalformed)
        );
    }

    #[test]
    fn verify_rejects_wrong_sig_len() {
        let pk = [0u8; ML_DSA_44_PK_LEN];
        let short_sig = [0u8; 100];
        assert_eq!(
            verify_pk(&pk, &[0u8; 64], &short_sig),
            Err(MlDsa44Error::SignatureInvalid)
        );
    }

    // ── liboqs-specific tests (only when oqs-backend is active) ──

    #[cfg(feature = "oqs-backend")]
    mod oqs_tests {
        use super::super::*;

        #[test]
        fn oqs_sign_then_verify_roundtrip() {
            oqs::init();
            let scheme = oqs::sig::Sig::new(oqs::sig::Algorithm::MlDsa44)
                .expect("ML-DSA-44 not available in liboqs");

            let (pk, sk) = scheme.keypair().expect("keygen failed");
            let message = b"test message for AN-DNA roundtrip";
            let signature = scheme.sign(message, &sk).expect("sign failed");

            assert!(verify_pk(pk.as_ref(), message, signature.as_ref()).is_ok());
        }

        #[test]
        fn oqs_verify_rejects_tampered_sig() {
            oqs::init();
            let scheme = oqs::sig::Sig::new(oqs::sig::Algorithm::MlDsa44)
                .expect("ML-DSA-44 not available in liboqs");

            let (pk, sk) = scheme.keypair().expect("keygen failed");
            let message = b"test message";
            let signature = scheme.sign(message, &sk).expect("sign failed");

            let mut tampered = signature.as_ref().to_vec();
            tampered[0] ^= 0xFF;

            assert_eq!(
                verify_pk(pk.as_ref(), message, &tampered),
                Err(MlDsa44Error::SignatureInvalid)
            );
        }

        #[test]
        fn oqs_verify_rejects_wrong_message() {
            oqs::init();
            let scheme = oqs::sig::Sig::new(oqs::sig::Algorithm::MlDsa44)
                .expect("ML-DSA-44 not available in liboqs");

            let (pk, sk) = scheme.keypair().expect("keygen failed");
            let message = b"correct message";
            let signature = scheme.sign(message, &sk).expect("sign failed");

            assert_eq!(
                verify_pk(pk.as_ref(), b"wrong message", signature.as_ref()),
                Err(MlDsa44Error::SignatureInvalid)
            );
        }

        #[test]
        fn oqs_verify_via_andna_interface() {
            oqs::init();
            let scheme = oqs::sig::Sig::new(oqs::sig::Algorithm::MlDsa44)
                .expect("ML-DSA-44 not available in liboqs");

            let (pk, sk) = scheme.keypair().expect("keygen failed");
            let pk_bytes = pk.as_ref();

            let mu = [0x42u8; MU_LEN];
            let signature = scheme.sign(&mu, &sk).expect("sign failed");

            let rho: &[u8; TE_RHO_LEN] = pk_bytes[..TE_RHO_LEN].try_into().unwrap();
            let t1: &[u8; TE_T1_LEN] = pk_bytes[TE_RHO_LEN..TE_RHO_LEN + TE_T1_LEN]
                .try_into()
                .unwrap();
            let sig_bytes: &[u8; SIG_LEN] = signature.as_ref().try_into().unwrap();

            assert!(verify(rho, t1, &mu, sig_bytes).is_ok());
        }

        #[test]
        fn oqs_key_and_sig_lengths_match_contracts() {
            oqs::init();
            let scheme = oqs::sig::Sig::new(oqs::sig::Algorithm::MlDsa44)
                .expect("ML-DSA-44 not available in liboqs");

            assert_eq!(
                scheme.length_public_key(),
                ML_DSA_44_PK_LEN,
                "liboqs pk len != our ML_DSA_44_PK_LEN"
            );
            assert_eq!(
                scheme.length_signature(),
                SIG_LEN,
                "liboqs sig len != our SIG_LEN"
            );
        }
    }
}
