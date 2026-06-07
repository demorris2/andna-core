//! Verification: reuse the pipeline for R1 + R2, then add the two seal-layer binding checks.

use crate::seal::SealedBundle;
use andna_contracts::{FRAME_V2_MU_PRE_OFF, MU_PRE_CTX_HASH_LEN, MU_PRE_CTX_HASH_OFF};
use andna_pipeline::{verify_and_authorize, CombinedDecision, Registry};
use serde::Serialize;
use sha3::{Digest, Sha3_256};

const DIGEST_LEN: usize = 32;

/// Three-valued verdict for each verification dimension.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    Yes,
    No,
    NotEvaluated,
}

impl Verdict {
    pub fn as_str(self) -> &'static str {
        match self {
            Verdict::Yes => "yes",
            Verdict::No => "no",
            Verdict::NotEvaluated => "not_evaluated",
        }
    }
}

/// The full seal verification result. Each dimension is independently falsifiable, and the
/// embedded [`CombinedDecision`] carries the R1 + R2 evidence (frame hash, verify error, R2
/// decision incl. its policy_digest).
#[derive(Clone, Debug, Serialize)]
pub struct SealVerifyResult {
    /// R1 cryptographically verified the seal frame (signature + identity bindings).
    pub authentic: bool,
    /// File + manifest match what was sealed. Only meaningful when `authentic`.
    pub unchanged: Verdict,
    /// Reason when `unchanged != Yes` (e.g. "manifest_hash_mismatch", "file_hash_mismatch").
    pub unchanged_detail: Option<String>,
    /// R2 authorization of the verified identity against the supplied registry.
    pub authorized: Verdict,
    /// Overall accept: `authentic && unchanged == Yes && authorized == Yes`.
    pub overall_accept: bool,
    /// SHA3-256 of the file bytes provided to verification (hex).
    pub computed_file_hash_hex: String,
    /// SHA3-256 of the supplied manifest (hex). Present only when `authentic`.
    pub computed_manifest_hash_hex: Option<String>,
    /// `ctx_hash` carried in the authentic frame (hex). Present only when `authentic`.
    pub frame_ctx_hash_hex: Option<String>,
    /// Full R1 + R2 evidence.
    pub combined: CombinedDecision,
}

impl SealVerifyResult {
    /// Pretty JSON evidence record.
    pub fn to_json_pretty(&self) -> String {
        serde_json::to_string_pretty(self).expect("SealVerifyResult is always serializable")
    }

    /// One-line strict human summary. No "safe"/"trusted"/"encrypted"/"malware-free" language.
    pub fn summary(&self) -> String {
        format!(
            "AUTHENTIC: {} | UNCHANGED: {} | AUTHORIZED: {}",
            if self.authentic { "yes" } else { "no" },
            self.unchanged.as_str(),
            self.authorized.as_str(),
        )
    }
}

/// Verify a sealed bundle against the file bytes and a registry snapshot.
///
/// R1 + R2 run via [`andna_pipeline::verify_and_authorize`] (no reimplemented verifier). The
/// seal layer then checks `manifest_hash == ctx_hash` and `file_hash == manifest.file_hash`.
/// The manifest/file checks are only meaningful when R1 accepted (an unauthentic frame's
/// `ctx_hash` is not trustworthy), so they report `NotEvaluated` otherwise — fail-closed.
pub fn verify_sealed(
    bundle: &SealedBundle,
    file_bytes: &[u8],
    registry: &Registry,
) -> SealVerifyResult {
    let file_hash = sha3_256(file_bytes);
    let computed_file_hash_hex = hex::encode(file_hash);

    // Bad hex -> empty bytes -> R1 LengthMismatch -> not authentic (no special-casing).
    let frame_bytes = hex::decode(&bundle.frame_hex).unwrap_or_default();
    let combined = verify_and_authorize(&frame_bytes, registry);
    let authentic = combined.r1.accepted;

    let (unchanged, unchanged_detail, computed_manifest_hash_hex, frame_ctx_hash_hex) = if authentic
    {
        // R1 accepted => frame_bytes is a full, well-formed frame; ctx_hash is authentic.
        let ctx = extract_ctx_hash(&frame_bytes);
        let manifest_hash = bundle.manifest.manifest_hash();
        let manifest_bound = manifest_hash == ctx;
        let file_matches = matches!(bundle.manifest.file_hash(), Ok(mh) if mh == file_hash);

        let (verdict, detail) = if !manifest_bound {
            (Verdict::No, Some("manifest_hash_mismatch".to_string()))
        } else if !file_matches {
            (Verdict::No, Some("file_hash_mismatch".to_string()))
        } else {
            (Verdict::Yes, None)
        };
        (verdict, detail, Some(hex::encode(manifest_hash)), Some(hex::encode(ctx)))
    } else {
        (Verdict::NotEvaluated, None, None, None)
    };

    let authorized = match combined.r2.stage2.as_str() {
        "AUTHORIZED" => Verdict::Yes,
        "NOT_AUTHORIZED" => Verdict::No,
        _ => Verdict::NotEvaluated,
    };

    let overall_accept = authentic && unchanged == Verdict::Yes && authorized == Verdict::Yes;

    SealVerifyResult {
        authentic,
        unchanged,
        unchanged_detail,
        authorized,
        overall_accept,
        computed_file_hash_hex,
        computed_manifest_hash_hex,
        frame_ctx_hash_hex,
        combined,
    }
}

fn sha3_256(bytes: &[u8]) -> [u8; DIGEST_LEN] {
    let mut h = Sha3_256::new();
    h.update(bytes);
    let out = h.finalize();
    let mut d = [0u8; DIGEST_LEN];
    d.copy_from_slice(&out);
    d
}

fn extract_ctx_hash(frame: &[u8]) -> [u8; MU_PRE_CTX_HASH_LEN] {
    let off = FRAME_V2_MU_PRE_OFF + MU_PRE_CTX_HASH_OFF;
    let mut ctx = [0u8; MU_PRE_CTX_HASH_LEN];
    ctx.copy_from_slice(&frame[off..off + MU_PRE_CTX_HASH_LEN]);
    ctx
}
