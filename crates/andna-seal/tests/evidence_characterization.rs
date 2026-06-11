//! Evidence characterization tests — threat-model hardening (doc 05).
//!
//! Run:
//!   cargo test -p andna-seal --test evidence_characterization -- --nocapture
//!
//! Pins the "digest_consistent() is not replay" boundary documented in doc 05.
//! RECONCILED against `evidence_contract.rs` (6 existing tests):
//!   - deterministic_section_replays_identically
//!   - runtime_fields_do_not_affect_digest
//!   - digest_changes_when_decision_changes
//!   - reject_evidence_isolates_authorization_failure
//!   - json_roundtrip_preserves_digest_consistency
//!   - digest_consistent_detects_edited_deterministic_section
//!
//! This file adds ONE net-new test: `digest_consistency_is_not_replay`, which
//! specifically asserts the doc 05 load-bearing statement: evidence WITHOUT the
//! original inputs supports digest-consistency only and cannot stand in for replay.

use andna_contracts::TE_DEVICE_ID16_LEN;
use andna_pipeline::{verified_facts_from_accepted_frame, Registry, RegistryEntry, VerifiedFacts};
use andna_seal::{
    seal_file, verify_sealed, RuntimeContext, SealEvidenceV1, SealedBundle, SoftwareProfileSigner,
};

fn signer() -> SoftwareProfileSigner {
    SoftwareProfileSigner::from_seed([0x77; 32], [0xBB; TE_DEVICE_ID16_LEN], 2)
}

fn facts_of(bundle: &SealedBundle) -> VerifiedFacts {
    let frame = hex::decode(&bundle.frame_hex).expect("frame hex");
    verified_facts_from_accepted_frame(&frame).expect("facts from frame")
}

fn authorizing_registry(facts: &VerifiedFacts) -> Registry {
    Registry {
        snapshot_seq: 1,
        as_of_unix_ms: 1_700_000_000_000,
        policy_version: "evidence-char-registry-v0".to_string(),
        entries: vec![RegistryEntry {
            device_id16: facts.device_id16,
            device_id32: facts.device_id32,
            authorized_te_hashes: vec![facts.te_hash],
            current_epoch: facts.epoch,
            revoked: false,
            frozen: false,
            recovery_hold: false,
            policy_version: "evidence-char-device-v0".to_string(),
        }],
    }
}

/// `digest_consistent()` is NOT equivalent to re-verification.
///
/// This test pins the doc 05 load-bearing statement:
///   "The evidence JSON alone does not replay."
///
/// Specifically: an evidence record that is internally consistent (`digest_consistent()`
/// returns true) does NOT prove that re-running verification on the same sidecar and
/// registry would produce the same verdict. `digest_consistent()` only proves that the
/// stored deterministic section matches its stored digest. Full replay requires the
/// original (file bytes, sidecar, registry).
///
/// The test demonstrates this by:
/// 1. Creating ACCEPT evidence for a file.
/// 2. Verifying the same sidecar against *different file bytes* — this produces REJECT.
/// 3. Asserting that the ORIGINAL ACCEPT evidence is STILL `digest_consistent()`.
///    (It is, because `digest_consistent()` does not re-run verification.)
/// 4. Asserting that the two evidence records have DIFFERENT digests — proving they
///    captured different decisions, so the original ACCEPT evidence describes a specific
///    past event, not a current property of the sidecar.
#[test]
fn digest_consistency_is_not_replay() {
    let original_file = b"the original, authentic content";
    let bundle = seal_file("doc.bin", original_file, None, &signer());
    let reg = authorizing_registry(&facts_of(&bundle));

    // Create ACCEPT evidence for the original file.
    let accept_evidence = SealEvidenceV1::from_result(
        &verify_sealed(&bundle, original_file, &reg),
        RuntimeContext::default(),
    );
    assert_eq!(
        accept_evidence.deterministic.result, "ACCEPT",
        "setup: original file must verify as ACCEPT"
    );
    assert!(
        accept_evidence.digest_consistent(),
        "setup: accept evidence must be internally consistent"
    );

    // Now verify the SAME sidecar against different bytes (simulates a file that has
    // changed since sealing, or a "rollback" scenario).
    let different_file = b"different content — not what was sealed";
    let reject_evidence = SealEvidenceV1::from_result(
        &verify_sealed(&bundle, different_file, &reg),
        RuntimeContext::default(),
    );
    assert_eq!(
        reject_evidence.deterministic.result, "REJECT",
        "different file bytes must produce REJECT"
    );

    // Core assertion: the original ACCEPT evidence is still digest_consistent() even
    // though a fresh verification of the same sidecar now produces REJECT.
    // This proves that digest_consistent() does not re-verify — it only checks the
    // internal coherence of the stored record.
    assert!(
        accept_evidence.digest_consistent(),
        "ACCEPT evidence remains digest_consistent() even after the same sidecar \
         produces REJECT against different input — digest_consistent() is not replay"
    );

    // The two evidence records have distinct digests, confirming they describe
    // different decision events. The ACCEPT evidence describes a past event;
    // it does not prove the current state of the file.
    assert_ne!(
        accept_evidence.evidence_digest_hex,
        reject_evidence.evidence_digest_hex,
        "ACCEPT and REJECT evidence for the same sidecar must have different digests"
    );
}
