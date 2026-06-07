//! Sealing: bind a file's manifest hash into `mu_pre.ctx_hash`, sign, and pack a Frame v2.

use crate::manifest::Manifest;
use crate::signer::{Signer, PK_E_LEN};
use andna_contracts::{
    DOMAIN_SEP, DOMAIN_SEP_LEN, FRAME_V2_LEN, MU_LEN, MU_PRE_CTX_HASH_LEN, MU_PRE_CTX_HASH_OFF,
    MU_PRE_DEVICE_ID32_LEN, MU_PRE_DEVICE_ID32_OFF, MU_PRE_DOMAIN_SEP_OFF, MU_PRE_EPOCH_LEN,
    MU_PRE_EPOCH_OFF, MU_PRE_LEN, MU_PRE_PK_HASH_OFF, MU_PRE_VERSION_OFF, MU_PRE_VERSION_VAL,
    PK_HASH_LEN, TE_DEVICE_ID16_LEN, TE_DEVICE_ID16_OFF, TE_EPOCH_LEN, TE_EPOCH_OFF, TE_LEN,
};
use serde::{Deserialize, Serialize};

pub const SIDECAR_SCHEMA_VERSION: &str = "andna-seal-sidecar-v0";
pub const FRAME_ENCODING: &str = "frame-v2-hex";

/// A detached seal sidecar: the manifest plus the hex-encoded Frame v2. The original file is
/// untouched (this is integrity/authenticity, not encryption).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SealedBundle {
    pub schema_version: String,
    pub manifest: Manifest,
    pub frame_hex: String,
    pub frame_encoding: String,
}

impl SealedBundle {
    /// Pretty JSON for writing the sidecar file (e.g. `name.ext.andna-seal.json`).
    pub fn to_json_pretty(&self) -> String {
        serde_json::to_string_pretty(self).expect("SealedBundle is always serializable")
    }
}

/// Seal raw file bytes: build the manifest, bind its hash into `ctx_hash`, sign with the
/// given identity, and pack the frame. File I/O is the caller's concern (pass the bytes),
/// which keeps this unit-testable without touching disk.
pub fn seal_file(
    file_name: impl Into<String>,
    file_bytes: &[u8],
    content_type: Option<String>,
    signer: &dyn Signer,
) -> SealedBundle {
    let manifest = Manifest::for_file(file_name, file_bytes, content_type);
    let manifest_hash = manifest.manifest_hash();

    let te = build_t_e(&signer.public_key(), signer.epoch(), &signer.device_id16());
    let mu_pre = build_mu_pre(&te, &manifest_hash);

    let mut mu = [0u8; MU_LEN];
    andna_transcript::mu_from_mu_pre(&mu_pre, &mut mu);
    let sig = signer.sign(&mu);

    let mut frame = [0u8; FRAME_V2_LEN];
    andna_codec::pack_frame_v2(&mu_pre, &te, &sig, &mut frame);

    SealedBundle {
        schema_version: SIDECAR_SCHEMA_VERSION.to_string(),
        manifest,
        frame_hex: hex::encode(frame),
        frame_encoding: FRAME_ENCODING.to_string(),
    }
}

/// `T_E = pk(rho||t1) || u64le(epoch) || device_id16`.
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

/// Build a correct `mu_pre` and bind `manifest_hash` into `ctx_hash`.
fn build_mu_pre(te: &[u8; TE_LEN], manifest_hash: &[u8; MU_PRE_CTX_HASH_LEN]) -> [u8; MU_PRE_LEN] {
    let mut mu_pre = [0u8; MU_PRE_LEN];

    let mut pk_hash = [0u8; PK_HASH_LEN];
    andna_transcript::pk_hash_from_te(te, &mut pk_hash);
    mu_pre[MU_PRE_PK_HASH_OFF..MU_PRE_PK_HASH_OFF + PK_HASH_LEN].copy_from_slice(&pk_hash);

    mu_pre[MU_PRE_DOMAIN_SEP_OFF..MU_PRE_DOMAIN_SEP_OFF + DOMAIN_SEP_LEN].copy_from_slice(&DOMAIN_SEP);
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

    // The file binding: manifest hash into ctx_hash. Signed over (so tampering breaks the
    // signature), but not interpreted by R1 — this crate owns its meaning.
    mu_pre[MU_PRE_CTX_HASH_OFF..MU_PRE_CTX_HASH_OFF + MU_PRE_CTX_HASH_LEN]
        .copy_from_slice(manifest_hash);

    // sid / n_d / n_s / policy_hash left zero (unchecked by R1; reserved for future binding).
    mu_pre
}
