//! # andna-pipeline — R1 (verify) + R2 (authorize) orchestration
//!
//! The end-to-end seam that connects the cryptographic verifier to the policy engine:
//!
//! ```text
//!   frame ─▶ R1 verify_frame_v2 ─▶ ACCEPT ─▶ extract VerifiedFacts ─▶ R2 authorize ─▶ decision
//!                               └▶ REJECT ─────────────────────────▶ R2 NOT_EVALUATED
//! ```
//!
//! ## Why this crate exists
//! `andna-core` (Stage 1) must not depend on `andna-r2`, and `andna-r2` (Stage 2) must stay
//! liboqs-free so it remains unit-testable without the crypto backend. The orchestration
//! needs both, so it lives here — the single crate where `oqs`/`liboqs` legitimately
//! re-enters to drive R2. R2 stays clean and is not modified by this crate.
//!
//! ## Fail-closed, end to end
//! [`verify_and_authorize`] hands R2 a [`Stage1Outcome::CryptoAccept`] only when
//! `verify_frame_v2` returned `Ok`. Any R1 rejection becomes [`Stage1Outcome::CryptoReject`],
//! and R2 can then only return `NOT_EVALUATED`. A registry that *would* authorize the device
//! cannot rescue a cryptographically invalid frame.
//!
//! ## Combined evidence
//! [`CombinedDecision`] pairs the R1 verdict (accept/reject, the rejecting `VerifyError` as a
//! stable string, and the SHA3-256 frame hash) with the full R2 [`Stage2Decision`] (which
//! carries its own snapshot-bound `policy_digest`). The combined record is serialized to
//! JSON; it is never deserialized here, so it derives `Serialize` only.

#![forbid(unsafe_code)]

use andna_audit::canonical::sha3_256;
use andna_contracts::{
    FRAME_V2_LEN, FRAME_V2_MU_PRE_OFF, FRAME_V2_TE_OFF, MU_PRE_DEVICE_ID32_LEN,
    MU_PRE_DEVICE_ID32_OFF, MU_PRE_EPOCH_LEN, MU_PRE_EPOCH_OFF, MU_PRE_PK_HASH_OFF, PK_HASH_LEN,
    TE_DEVICE_ID16_LEN, TE_DEVICE_ID16_OFF,
};
use andna_core::{verify_frame_v2, VerifyError};
use serde::Serialize;

// Re-export the R2 surface callers/tests need. Limited to symbols andna-r2 exports at its
// root, so this compiles against the policy engine as it stands.
pub use andna_r2::{
    authorize, Registry, RegistryEntry, RegistryError, SnapshotId, Stage1Outcome, Stage2Decision,
    Stage2Status, VerifiedFacts,
};

// Epoch field is read as a u64.
const _: () = assert!(MU_PRE_EPOCH_LEN == 8);

/// The Stage-1 (R1) portion of the combined evidence.
#[derive(Clone, Debug, Serialize)]
pub struct R1Evidence {
    /// Raw R1 verdict for this frame.
    pub accepted: bool,
    /// Stable error string when `accepted == false`; `None` when accepted.
    pub verify_error: Option<String>,
    /// SHA3-256 of the exact frame bytes (hex), via `andna_audit::canonical::sha3_256`.
    pub frame_hash_hex: String,
}

/// R1 verdict + R2 decision for one frame. Serialized as the R2-side evidence record.
#[derive(Clone, Debug, Serialize)]
pub struct CombinedDecision {
    pub r1: R1Evidence,
    pub r2: Stage2Decision,
}

impl CombinedDecision {
    /// Pretty JSON for the combined decision (the R2-side evidence artifact).
    pub fn to_json_pretty(&self) -> String {
        serde_json::to_string_pretty(self).expect("CombinedDecision is always serializable")
    }
}

/// Stable, lowercase string for each `VerifyError` variant. Used in evidence instead of
/// `Debug` so the wire form is a frozen contract independent of Rust formatting.
fn verify_error_str(e: VerifyError) -> &'static str {
    match e {
        VerifyError::LengthMismatch => "length_mismatch",
        VerifyError::MuPreMalformed => "mu_pre_malformed",
        VerifyError::TeMalformed => "te_malformed",
        VerifyError::SigMalformed => "sig_malformed",
        VerifyError::PkHashMismatch => "pk_hash_mismatch",
        VerifyError::EpochMismatch => "epoch_mismatch",
        VerifyError::DeviceIdMismatch => "device_id_mismatch",
        VerifyError::SignatureInvalid => "signature_invalid",
        VerifyError::Internal => "internal",
    }
}

/// Extract R1-confirmed facts from a frame that R1 has **already ACCEPTED**.
///
/// PRECONDITION: `verify_frame_v2(frame)` returned `Ok` for this exact frame. This performs
/// NO verification — it reads fields at the canonical Frame-v2 offsets. Implemented here (not
/// pulled from andna-r2) so the pipeline doesn't depend on R2 re-exporting an extraction
/// helper. Returns `None` only on a wrong-length frame.
pub fn verified_facts_from_accepted_frame(frame: &[u8]) -> Option<VerifiedFacts> {
    if frame.len() != FRAME_V2_LEN {
        return None;
    }
    let mu = FRAME_V2_MU_PRE_OFF;
    let te = FRAME_V2_TE_OFF;

    let mut te_hash = [0u8; PK_HASH_LEN];
    te_hash.copy_from_slice(&frame[mu + MU_PRE_PK_HASH_OFF..mu + MU_PRE_PK_HASH_OFF + PK_HASH_LEN]);

    let mut device_id32 = [0u8; MU_PRE_DEVICE_ID32_LEN];
    device_id32.copy_from_slice(
        &frame[mu + MU_PRE_DEVICE_ID32_OFF..mu + MU_PRE_DEVICE_ID32_OFF + MU_PRE_DEVICE_ID32_LEN],
    );

    let mut epoch_le = [0u8; MU_PRE_EPOCH_LEN];
    epoch_le
        .copy_from_slice(&frame[mu + MU_PRE_EPOCH_OFF..mu + MU_PRE_EPOCH_OFF + MU_PRE_EPOCH_LEN]);
    let epoch = u64::from_le_bytes(epoch_le);

    let mut device_id16 = [0u8; TE_DEVICE_ID16_LEN];
    device_id16.copy_from_slice(
        &frame[te + TE_DEVICE_ID16_OFF..te + TE_DEVICE_ID16_OFF + TE_DEVICE_ID16_LEN],
    );

    Some(VerifiedFacts {
        device_id16,
        device_id32,
        epoch,
        te_hash,
    })
}

/// Run the full R1 → R2 pipeline for one frame against one registry snapshot.
///
/// On R1 ACCEPT, facts are extracted and R2 evaluates policy. On R1 REJECT, R2 is handed
/// [`Stage1Outcome::CryptoReject`] and returns `NOT_EVALUATED` (fail-closed). Fact extraction
/// after ACCEPT cannot fail (R1 only accepts a `FRAME_V2`-length frame), so a `None` there
/// would mean R1 accepted a malformed frame — surfaced as a panic, not a silent authorization.
pub fn verify_and_authorize(frame: &[u8], registry: &Registry) -> CombinedDecision {
    let frame_hash_hex = hex::encode(sha3_256(frame));

    let (stage1, r1) = match verify_frame_v2(frame) {
        Ok(()) => {
            let facts = verified_facts_from_accepted_frame(frame)
                .expect("R1 ACCEPT guarantees a well-formed FRAME_V2-length frame");
            (
                Stage1Outcome::CryptoAccept(facts),
                R1Evidence {
                    accepted: true,
                    verify_error: None,
                    frame_hash_hex,
                },
            )
        }
        Err(e) => (
            Stage1Outcome::CryptoReject,
            R1Evidence {
                accepted: false,
                verify_error: Some(verify_error_str(e).to_string()),
                frame_hash_hex,
            },
        ),
    };

    let r2 = authorize(&stage1, registry);
    CombinedDecision { r1, r2 }
}
