//! D0 -> ML-DSA-44 bridge: seeded `KeyGen_internal(xi_E)`, `T_E` assembly, and
//! scoped signing.
//!
//! Backend (validation status):
//!   * Official algorithm : FIPS 204 ML-DSA (ML-DSA-44).
//!   * Implementation     : `fips204` crate, pinned `=0.4.6` — an IMPLEMENTATION
//!                          CANDIDATE, not official NIST software.
//!   * Validation status  : NOT claimed as FIPS 140-3 / CAVP validated.
//!   * Use                : D0 seeded keygen ONLY.
//!
//! SECRET-KEY LIFECYCLE / PROFILE (required hardening):
//!   `EpochKeypair` holds a `fips204` `PrivateKey`. This crate does NOT independently
//!   confirm that `fips204`'s `PrivateKey` zeroizes on drop, and cannot force-zeroize
//!   its opaque internals from the outside. Therefore:
//!     * `EpochKeypair` is SOFTWARE-PROFILE ONLY. The architecture's hardware-bound /
//!       non-extractable claim does NOT hold while `sk_E` lives in ordinary process
//!       memory. For hardware profiles, signing must occur inside the protected
//!       boundary and `sk_E` must never enter host memory.
//!     * Procurement-grade host paths SHOULD prefer [`derive_epoch_public`] (retains
//!       and exposes no secret key — the backend generates `sk_E` internally and drops
//!       it in scope) for publishing `T_E`, and [`sign_in_epoch`] (derives, signs, and
//!       drops `sk_E` within a single call) to minimize `sk_E` lifetime. Neither relies
//!       on `fips204`'s drop semantics.
//!   RELEASE GATE: confirm and pin `fips204`'s `PrivateKey` drop behavior before
//!   making any in-memory `sk_E` lifecycle / zeroization claim.
//!
//! Dual-backend isolation: R1 signature VERIFICATION stays on liboqs/oqs-sys in its
//! own crates (`andna-mldsa44` / `andna-core`), which do NOT depend on andna-d0. The
//! cross-backend equality KAT lives in `crates/core/tests/` (it dev-depends on
//! andna-d0); andna-d0 itself pulls no liboqs.
//!
//! Constants: T_E / signature / hash sizes come from the shared `andna-contracts`
//! interface (`TE_LEN`, `SIG_LEN`, `PK_HASH_LEN`, `TE_*`). The ML-DSA-44 public-key
//! length is derived from the contracts T_E field widths (`TE_RHO_LEN + TE_T1_LEN`)
//! as a private bridge alias, so no parallel public constant is introduced and the
//! bridge takes no dependency on the (oqs-bearing) `andna-mldsa44` crate.
//!
//! API NOTE: confirm `KG::keygen_from_seed`, `SerDes::into_bytes`, and the
//! `Signer::try_sign` return shape against the pinned `fips204 =0.4.6` on first build.

use crate::derive::{derive_xi, D0Context, D0Error, SecretState};
use andna_contracts::{
    PK_HASH_LEN, SIG_LEN, TE_DEVICE_ID16_LEN, TE_DEVICE_ID16_OFF, TE_EPOCH_LEN, TE_EPOCH_OFF,
    TE_LEN, TE_RHO_LEN, TE_T1_LEN,
};
use sha3::digest::{ExtendableOutput, Update, XofReader};
use sha3::Shake256;

use fips204::ml_dsa_44::{PrivateKey, KG};
use fips204::traits::{KeyGen, SerDes, Signer};

/// ML-DSA-44 public-key length (rho || t1), derived from the shared T_E field widths.
/// Private bridge alias — not a parallel public interface constant.
const PK_E_LEN: usize = TE_RHO_LEN + TE_T1_LEN; // 1312

// Compile-time guards tying the bridge to the shared contract.
const _: () = assert!(PK_E_LEN == 1312);
const _: () = assert!(PK_E_LEN == TE_EPOCH_OFF); // pk fills T_E[0..epoch_off]
const _: () = assert!(TE_EPOCH_LEN == 8); // u64le epoch
const _: () = assert!(PK_HASH_LEN == 64); // the bridge emits SHAKE256(T_E, 64)

/// Public epoch material. No secret key is retained or exposed by the API — the
/// backend (fips204) still generates `sk_E` internally during keygen and drops it in
/// scope. Preferred procurement-grade output for publishing the epoch / feeding R1.
pub struct EpochPublic {
    pub pk: [u8; PK_E_LEN],
    pub t_e: [u8; TE_LEN],
    pub t_e_hash64: [u8; PK_HASH_LEN],
}

/// SOFTWARE-PROFILE-ONLY keypair holding the `fips204` signing key opaquely (no `sk`
/// byte export). See the module SECRET-KEY LIFECYCLE note.
pub struct EpochKeypair {
    pk: [u8; PK_E_LEN],
    sk: PrivateKey,
}

impl EpochKeypair {
    /// The 1312-byte FIPS 204 ML-DSA-44 public key (rho || t1).
    pub fn public_key_bytes(&self) -> &[u8; PK_E_LEN] {
        &self.pk
    }
    /// Opaque signing key (software-profile signing). No byte export is offered here.
    pub fn private_key(&self) -> &PrivateKey {
        &self.sk
    }
}

/// Run ML-DSA-44 `KeyGen_internal(xi_E)`. `xi_E` is an auto-wiping `Zeroizing` and is
/// dropped (wiped) at the end of this call. The pk byte length is checked (no silent
/// truncation). Returns the public-key bytes plus the opaque `sk`.
fn keygen_internal(
    state: &SecretState,
    ctx: &D0Context,
) -> Result<([u8; PK_E_LEN], PrivateKey), D0Error> {
    let xi = derive_xi(state, ctx); // Zeroizing<[u8; 32]>, wiped on drop
    let (pk, sk) = KG::keygen_from_seed(&*xi); // == ML-DSA-44.KeyGen_internal(xi)
    let pk_full = pk.into_bytes();
    if pk_full.len() != PK_E_LEN {
        return Err(D0Error::MldsaKeygen);
    }
    let mut pk_arr = [0u8; PK_E_LEN];
    pk_arr.copy_from_slice(&pk_full);
    Ok((pk_arr, sk))
}

/// Build the epoch public material (`pk_E`, `T_E`, `T_E_hash64`). The backend
/// generates `sk_E` internally during keygen; this call retains and exposes NO secret
/// key — `sk_E` is dropped in scope. Preferred for publishing the epoch.
pub fn derive_epoch_public(state: &SecretState, ctx: &D0Context) -> Result<EpochPublic, D0Error> {
    let (pk, _sk) = keygen_internal(state, ctx)?; // _sk generated by the backend, dropped at end of fn
    let t_e = build_t_e(&pk, ctx.epoch, &ctx.device_id16);
    let t_e_hash64 = t_e_hash64(&t_e);
    Ok(EpochPublic { pk, t_e, t_e_hash64 })
}

/// Derive the epoch keypair, sign `msg` with the (NIST) context string `sig_ctx`, and
/// drop `sk_E` within this call — minimizing `sk_E` lifetime. Returns the 2420-byte
/// ML-DSA-44 signature. Does not rely on `fips204` drop semantics.
pub fn sign_in_epoch(
    state: &SecretState,
    ctx: &D0Context,
    msg: &[u8],
    sig_ctx: &[u8],
) -> Result<[u8; SIG_LEN], D0Error> {
    let (_pk, sk) = keygen_internal(state, ctx)?;
    // fips204 try_sign returns the signature as a fixed [u8; SIG_LEN]; sk drops at end
    // of scope. If a future version returns a newtype, convert here.
    let sig = sk.try_sign(msg, sig_ctx).map_err(|_| D0Error::MldsaKeygen)?;
    Ok(sig)
}

/// SOFTWARE-PROFILE ONLY (see module note). Derives the epoch keypair and RETAINS
/// `sk_E` in [`EpochKeypair`]. Prefer [`derive_epoch_public`] + [`sign_in_epoch`] for
/// procurement paths; provided for software-profile callers that must hold the key.
pub fn derive_epoch_keypair(state: &SecretState, ctx: &D0Context) -> Result<EpochKeypair, D0Error> {
    let (pk, sk) = keygen_internal(state, ctx)?;
    Ok(EpochKeypair { pk, sk })
}

/// `T_E = pk_E || u64le(epoch) || device_id16`  (`TE_LEN` bytes), laid out at the
/// shared contract offsets.
pub fn build_t_e(
    pk: &[u8; PK_E_LEN],
    epoch: u64,
    device_id16: &[u8; TE_DEVICE_ID16_LEN],
) -> [u8; TE_LEN] {
    let mut t = [0u8; TE_LEN];
    t[..PK_E_LEN].copy_from_slice(pk); // rho || t1
    t[TE_EPOCH_OFF..TE_EPOCH_OFF + TE_EPOCH_LEN].copy_from_slice(&epoch.to_le_bytes());
    t[TE_DEVICE_ID16_OFF..TE_DEVICE_ID16_OFF + TE_DEVICE_ID16_LEN].copy_from_slice(device_id16);
    t
}

/// `T_E_hash64 = SHAKE256(T_E, 64)` — feeds R1 `mu_pre.pk_hash`.
pub fn t_e_hash64(t_e: &[u8; TE_LEN]) -> [u8; PK_HASH_LEN] {
    let mut h = Shake256::default();
    h.update(t_e);
    let mut reader = h.finalize_xof();
    let mut out = [0u8; PK_HASH_LEN];
    reader.read(&mut out);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use fips204::traits::Verifier;

    /// In-crate (fips204-only) determinism + self-consistency. `KeyGen_internal` is
    /// deterministic, so a fixed `xi` yields a fixed pk; the matching sk signs
    /// verifiably. (Cross-backend equality against liboqs is the crates/core KAT.)
    #[test]
    fn keygen_from_seed_deterministic_and_self_consistent() {
        let xi = [7u8; 32];
        let (pk_a, sk) = KG::keygen_from_seed(&xi);
        let (pk_b, _) = KG::keygen_from_seed(&xi);

        let msg = b"andna-d0 interop";
        let sig = sk.try_sign(msg, &[]).expect("fips204 sign");
        assert!(pk_a.verify(msg, &sig, &[]), "self-verify failed");

        assert_eq!(
            pk_a.into_bytes(),
            pk_b.into_bytes(),
            "keygen_from_seed is not deterministic for a fixed xi"
        );
    }

    /// T_E layout and the shared interface length constants.
    #[test]
    fn t_e_layout_and_lengths() {
        assert_eq!(TE_LEN, 1336);
        assert_eq!(PK_HASH_LEN, 64);
        assert_eq!(PK_E_LEN, 1312);
        assert_eq!(SIG_LEN, 2420);

        let pk = [0xABu8; PK_E_LEN];
        let dev = [0xCDu8; TE_DEVICE_ID16_LEN];
        let epoch: u64 = 0x0102_0304_0506_0708;
        let t = build_t_e(&pk, epoch, &dev);

        assert_eq!(t.len(), TE_LEN);
        assert_eq!(&t[..PK_E_LEN], &pk[..]);
        assert_eq!(&t[TE_EPOCH_OFF..TE_EPOCH_OFF + TE_EPOCH_LEN], &epoch.to_le_bytes()[..]);
        assert_eq!(&t[TE_DEVICE_ID16_OFF..TE_DEVICE_ID16_OFF + TE_DEVICE_ID16_LEN], &dev[..]);

        let h = t_e_hash64(&t);
        assert_eq!(h.len(), PK_HASH_LEN);
    }
}
