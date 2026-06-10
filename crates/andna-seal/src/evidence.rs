//! The stable seal-verification evidence contract (`andna-seal-evidence-v1`).
//!
//! [`SealEvidenceV1`] is the durable, replayable record of one `verify_sealed` decision —
//! the artifact `verify-file --evidence-out` writes and that contract tests assert against.
//! Its design rule is the separation the rest of the system already follows:
//!
//! * [`DeterministicEvidence`] — pure function of (sealed bundle, file bytes, registry
//!   snapshot). Re-running the same verification MUST reproduce this section byte-for-byte.
//!   It is the ONLY input to [`SealEvidenceV1::evidence_digest_hex`].
//! * [`RuntimeContext`] — environment facts (paths, tool version). Useful for humans and
//!   incident reconstruction, but explicitly EXCLUDED from the digest: two machines
//!   verifying the same seal from different directories produce the same digest.
//! * `display` — the human summary line. Presentation only; also excluded.
//!
//! `evidence_digest` = SHA3-256 over a domain-separated, length-prefixed canonical encoding
//! of the deterministic section (NOT over its JSON), so serializer formatting can never
//! change the digest. Contract tests should assert deterministic fields and the digest, and
//! treat runtime/display fields as informational.

use crate::lp;
use crate::verify::{SealVerifyResult, Verdict};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};

const EVIDENCE_DOMAIN: &[u8] = b"ANDNA-SEAL-EVIDENCE-v1";

pub const EVIDENCE_SCHEMA_VERSION: &str = "andna-seal-evidence-v1";

/// Replayable core of the decision: a pure function of (bundle, file bytes, registry
/// snapshot). Field order here is the canonical encoding order — append new fields at the
/// end under a bumped schema version, never reorder.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeterministicEvidence {
    /// "ACCEPT" | "REJECT" — overall decision (`overall_accept`).
    pub result: String,
    /// R1 authenticity verdict.
    pub authentic: bool,
    /// "yes" | "no" | "not_evaluated".
    pub unchanged: String,
    /// e.g. "manifest_hash_mismatch" | "file_hash_mismatch" (when unchanged == "no").
    pub unchanged_detail: Option<String>,
    /// "yes" | "no" | "not_evaluated".
    pub authorized: String,
    /// R2 reason code (e.g. "registry_entry_valid", "no_registry_entry", "stage1_reject").
    pub reason_code: String,
    /// R1 reject error when not authentic (e.g. "signature_invalid"); None when accepted.
    pub verify_error: Option<String>,

    // ── hashes ──
    /// SHA3-256 of the file bytes presented to verification.
    pub file_hash_hex: String,
    /// SHA3-256 of the exact frame bytes (R1 evidence).
    pub frame_hash_hex: String,
    /// Canonical manifest hash (present when authentic).
    pub manifest_hash_hex: Option<String>,
    /// ctx_hash carried in the authentic frame (present when authentic).
    pub frame_ctx_hash_hex: Option<String>,

    // ── identity / policy facts (verbatim from the R2 decision record) ──
    pub epoch: u64,
    pub device_id32_hex: String,
    pub te_hash_hex: String,
    pub attestation_status: String,
    pub registry_policy_version: String,
    pub entry_policy_version: Option<String>,
    pub snapshot_seq: u64,
    pub as_of_unix_ms: u64,
    pub registry_snapshot_hash_hex: String,
    /// R2 snapshot-bound policy digest (None when policy was not evaluated).
    pub policy_digest_hex: Option<String>,
}

/// Environment facts. NEVER part of the evidence digest; contract tests must not require
/// specific values here.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeContext {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file_path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seal_path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub registry_path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verified_at_unix_ms: Option<u64>,
}

/// The full evidence record written to disk.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SealEvidenceV1 {
    pub schema_version: String,
    pub deterministic: DeterministicEvidence,
    /// SHA3-256 over the canonical encoding of `deterministic` (hex). Recomputable by any
    /// party from the deterministic section alone.
    pub evidence_digest_hex: String,
    pub runtime: RuntimeContext,
    /// Human-readable summary (presentation only).
    pub display_summary: String,
}

impl SealEvidenceV1 {
    /// Build the evidence record from a verification result plus runtime context.
    pub fn from_result(result: &SealVerifyResult, runtime: RuntimeContext) -> SealEvidenceV1 {
        let r2 = &result.combined.r2;
        let det = DeterministicEvidence {
            result: if result.overall_accept {
                "ACCEPT"
            } else {
                "REJECT"
            }
            .to_string(),
            authentic: result.authentic,
            unchanged: result.unchanged.as_str().to_string(),
            unchanged_detail: result.unchanged_detail.clone(),
            authorized: result.authorized.as_str().to_string(),
            reason_code: r2.reason.clone(),
            verify_error: result.combined.r1.verify_error.clone(),
            file_hash_hex: result.computed_file_hash_hex.clone(),
            frame_hash_hex: result.combined.r1.frame_hash_hex.clone(),
            manifest_hash_hex: result.computed_manifest_hash_hex.clone(),
            frame_ctx_hash_hex: result.frame_ctx_hash_hex.clone(),
            epoch: r2.epoch,
            device_id32_hex: r2.device_id32_hex.clone(),
            te_hash_hex: r2.te_hash_hex.clone(),
            attestation_status: r2.attestation_status.clone(),
            registry_policy_version: r2.registry_policy_version.clone(),
            entry_policy_version: r2.entry_policy_version.clone(),
            snapshot_seq: r2.snapshot_seq,
            as_of_unix_ms: r2.as_of_unix_ms,
            registry_snapshot_hash_hex: r2.snapshot_hash_hex.clone(),
            policy_digest_hex: r2.policy_digest_hex.clone(),
        };
        let evidence_digest_hex = hex::encode(det.canonical_digest());
        SealEvidenceV1 {
            schema_version: EVIDENCE_SCHEMA_VERSION.to_string(),
            deterministic: det,
            evidence_digest_hex,
            runtime,
            display_summary: result.summary(),
        }
    }

    /// Recompute the digest from the deterministic section and compare. Lets any holder of
    /// the JSON detect a tampered or hand-edited deterministic section.
    pub fn digest_consistent(&self) -> bool {
        hex::encode(self.deterministic.canonical_digest()) == self.evidence_digest_hex
    }

    /// Pretty JSON for `--evidence-out`.
    pub fn to_json_pretty(&self) -> String {
        serde_json::to_string_pretty(self).expect("SealEvidenceV1 is always serializable")
    }
}

impl DeterministicEvidence {
    /// Domain-separated, length-prefixed canonical encoding (NOT JSON). `Option` fields are
    /// tagged 0x00 (absent) / 0x01 (present) before the value so None and Some("") differ.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        fn lp_opt(buf: &mut Vec<u8>, v: &Option<String>) {
            match v {
                None => buf.push(0x00),
                Some(s) => {
                    buf.push(0x01);
                    lp(buf, s.as_bytes());
                }
            }
        }
        let mut buf = Vec::new();
        buf.extend_from_slice(EVIDENCE_DOMAIN);
        lp(&mut buf, self.result.as_bytes());
        buf.push(self.authentic as u8);
        lp(&mut buf, self.unchanged.as_bytes());
        lp_opt(&mut buf, &self.unchanged_detail);
        lp(&mut buf, self.authorized.as_bytes());
        lp(&mut buf, self.reason_code.as_bytes());
        lp_opt(&mut buf, &self.verify_error);
        lp(&mut buf, self.file_hash_hex.as_bytes());
        lp(&mut buf, self.frame_hash_hex.as_bytes());
        lp_opt(&mut buf, &self.manifest_hash_hex);
        lp_opt(&mut buf, &self.frame_ctx_hash_hex);
        buf.extend_from_slice(&self.epoch.to_le_bytes());
        lp(&mut buf, self.device_id32_hex.as_bytes());
        lp(&mut buf, self.te_hash_hex.as_bytes());
        lp(&mut buf, self.attestation_status.as_bytes());
        lp(&mut buf, self.registry_policy_version.as_bytes());
        lp_opt(&mut buf, &self.entry_policy_version);
        buf.extend_from_slice(&self.snapshot_seq.to_le_bytes());
        buf.extend_from_slice(&self.as_of_unix_ms.to_le_bytes());
        lp(&mut buf, self.registry_snapshot_hash_hex.as_bytes());
        lp_opt(&mut buf, &self.policy_digest_hex);
        buf
    }

    /// SHA3-256 over [`Self::canonical_bytes`].
    pub fn canonical_digest(&self) -> [u8; 32] {
        let mut h = Sha3_256::new();
        h.update(self.canonical_bytes());
        let out = h.finalize();
        let mut d = [0u8; 32];
        d.copy_from_slice(&out);
        d
    }
}

// Keep `Verdict` referenced so the contract between the two modules is explicit: the
// evidence strings come from `Verdict::as_str`, never re-derived ad hoc.
const _: fn(Verdict) -> &'static str = Verdict::as_str;
