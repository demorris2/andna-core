//! The sealing identity abstraction and the default software-profile backend.

use andna_contracts::{MU_LEN, SIG_LEN, TE_DEVICE_ID16_LEN, TE_RHO_LEN, TE_T1_LEN};
use fips204::ml_dsa_44::KG;
use fips204::traits::{KeyGen, SerDes, Signer as Fips204Signer};
use zeroize::Zeroizing;

/// ML-DSA-44 public key length (`rho || t1`).
pub const PK_E_LEN: usize = TE_RHO_LEN + TE_T1_LEN; // 1312

/// A sealing identity: produces its ML-DSA-44 public key, signs a 64-byte `mu`, and reports
/// the `(device_id16, epoch)` stamped into the frame.
///
/// This trait is the architecture. The [`SoftwareProfileSigner`] below is the default
/// backend; a D0-ratchet backend can be added later (its epoch evolves, so it must be paired
/// with verify-as-of-snapshot semantics so its seals don't expire under R2 epoch-freshness).
pub trait Signer {
    /// The 1312-byte ML-DSA-44 public key (`rho || t1`) for this identity.
    fn public_key(&self) -> [u8; PK_E_LEN];
    /// Sign the 64-byte transcript `mu`, returning the 2420-byte ML-DSA-44 signature.
    fn sign(&self, mu: &[u8; MU_LEN]) -> [u8; SIG_LEN];
    /// 16-byte device identifier stamped into `T_E`.
    fn device_id16(&self) -> [u8; TE_DEVICE_ID16_LEN];
    /// Epoch stamped into the frame. A stable epoch yields durable (non-expiring) seals.
    fn epoch(&self) -> u64;
}

/// SOFTWARE-PROFILE sealer backend — a NON-PRODUCTION identity.
///
/// Deterministic ML-DSA-44 keypair from a 32-byte seed, with a stable epoch (→ durable
/// seals). The keypair is re-derived per operation and dropped immediately, so the only
/// retained secret is the seed, which is zeroized on drop. This proves the file-seal
/// workflow; it is not a hardware-rooted or clone-resistant device identity.
pub struct SoftwareProfileSigner {
    seed: Zeroizing<[u8; 32]>,
    device_id16: [u8; TE_DEVICE_ID16_LEN],
    epoch: u64,
}

impl SoftwareProfileSigner {
    /// Create a software-profile signer from a 32-byte seed and a fixed identity/epoch.
    pub fn from_seed(seed: [u8; 32], device_id16: [u8; TE_DEVICE_ID16_LEN], epoch: u64) -> Self {
        Self { seed: Zeroizing::new(seed), device_id16, epoch }
    }
}

impl Signer for SoftwareProfileSigner {
    fn public_key(&self) -> [u8; PK_E_LEN] {
        let (pk, _sk) = KG::keygen_from_seed(&*self.seed);
        let bytes = pk.into_bytes();
        let mut out = [0u8; PK_E_LEN];
        out.copy_from_slice(&bytes);
        out
    }

    fn sign(&self, mu: &[u8; MU_LEN]) -> [u8; SIG_LEN] {
        // Re-derive the keypair so the private key's lifetime is confined to this call.
        let (_pk, sk) = KG::keygen_from_seed(&*self.seed);
        sk.try_sign(mu, &[]).expect("ML-DSA-44 signing over a 64-byte mu cannot fail")
    }

    fn device_id16(&self) -> [u8; TE_DEVICE_ID16_LEN] {
        self.device_id16
    }

    fn epoch(&self) -> u64 {
        self.epoch
    }
}
