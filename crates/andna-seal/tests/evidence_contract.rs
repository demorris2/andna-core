//! Evidence contract tests (gated on `oqs-backend`; verification calls the real R1).
//!
//! Run:
//!   cargo test -p andna-seal --test evidence_contract -- --nocapture
//!
//! Enforces the `andna-seal-evidence-v1` contract:
//!   * deterministic section is byte-identical across repeated verifications of the same
//!     (bundle, file, registry) — including the evidence digest;
//!   * runtime fields (paths, tool version, timestamps) NEVER affect the digest;
//!   * the digest is sensitive to decision changes (tamper flips it);
//!   * REJECT evidence carries the isolating detail (unchanged_detail / reason_code);
//!   * JSON roundtrips and `digest_consistent()` detects deterministic-section edits.

use andna_contracts::TE_DEVICE_ID16_LEN;
use andna_pipeline::{verified_facts_from_accepted_frame, Registry, RegistryEntry, VerifiedFacts};
use andna_seal::{
    seal_file, verify_sealed, RuntimeContext, SealEvidenceV1, SealedBundle, SoftwareProfileSigner,
    EVIDENCE_SCHEMA_VERSION,
};

// ── determinism ────────────────────────────────────────────────────────────────

#[test]
fn deterministic_section_replays_identically() {
    let file = b"evidence determinism";
    let bundle = seal_file("e.txt", file, None, &signer());
    let reg = authorizing_registry(&facts_of(&bundle));

    let e1 = SealEvidenceV1::from_result(
        &verify_sealed(&bundle, file, &reg),
        RuntimeContext::default(),
    );
    let e2 = SealEvidenceV1::from_result(
        &verify_sealed(&bundle, file, &reg),
        RuntimeContext::default(),
    );

    assert_eq!(e1.schema_version, EVIDENCE_SCHEMA_VERSION);
    assert_eq!(e1.deterministic, e2.deterministic);
    assert_eq!(e1.evidence_digest_hex, e2.evidence_digest_hex);
    // Canonical bytes themselves are identical — the digest equality is not coincidental.
    assert_eq!(
        e1.deterministic.canonical_bytes(),
        e2.deterministic.canonical_bytes()
    );
    assert_eq!(e1.deterministic.result, "ACCEPT");
}

#[test]
fn runtime_fields_do_not_affect_digest() {
    let file = b"runtime independence";
    let bundle = seal_file("e.txt", file, None, &signer());
    let reg = authorizing_registry(&facts_of(&bundle));
    let result = verify_sealed(&bundle, file, &reg);

    let machine_a = RuntimeContext {
        file_path: Some("C:\\releases\\e.txt".to_string()),
        seal_path: Some("C:\\releases\\e.txt.andna-seal.json".to_string()),
        registry_path: Some("C:\\registry\\prod.json".to_string()),
        tool_version: Some("andna 0.1.0".to_string()),
        verified_at_unix_ms: Some(1_800_000_000_000),
    };
    let machine_b = RuntimeContext {
        file_path: Some("/home/op/e.txt".to_string()),
        seal_path: None,
        registry_path: Some("/etc/andna/registry.json".to_string()),
        tool_version: Some("andna 0.2.0-dev".to_string()),
        verified_at_unix_ms: Some(1_900_000_000_001),
    };

    let ea = SealEvidenceV1::from_result(&result, machine_a);
    let eb = SealEvidenceV1::from_result(&result, machine_b);
    assert_ne!(ea.runtime, eb.runtime);
    assert_eq!(ea.deterministic, eb.deterministic);
    assert_eq!(ea.evidence_digest_hex, eb.evidence_digest_hex);
}

// ── sensitivity ────────────────────────────────────────────────────────────────

#[test]
fn digest_changes_when_decision_changes() {
    let file = b"sensitivity";
    let bundle = seal_file("e.txt", file, None, &signer());
    let reg = authorizing_registry(&facts_of(&bundle));

    let accept = SealEvidenceV1::from_result(
        &verify_sealed(&bundle, file, &reg),
        RuntimeContext::default(),
    );
    let tampered = b"sensitivity!";
    let reject = SealEvidenceV1::from_result(
        &verify_sealed(&bundle, tampered, &reg),
        RuntimeContext::default(),
    );

    assert_eq!(accept.deterministic.result, "ACCEPT");
    assert_eq!(reject.deterministic.result, "REJECT");
    assert_eq!(
        reject.deterministic.unchanged_detail.as_deref(),
        Some("file_hash_mismatch")
    );
    assert_ne!(accept.evidence_digest_hex, reject.evidence_digest_hex);
    assert_ne!(
        accept.deterministic.file_hash_hex,
        reject.deterministic.file_hash_hex
    );
}

#[test]
fn reject_evidence_isolates_authorization_failure() {
    let file = b"authz isolation";
    let bundle = seal_file("e.txt", file, None, &signer());
    let e = SealEvidenceV1::from_result(
        &verify_sealed(&bundle, file, &empty_registry()),
        RuntimeContext::default(),
    );
    let d = &e.deterministic;
    assert_eq!(d.result, "REJECT");
    assert!(d.authentic);
    assert_eq!(d.unchanged, "yes");
    assert_eq!(d.authorized, "no");
    assert_eq!(d.reason_code, "no_registry_entry");
    // Snapshot identity of the registry the decision was made against is bound in.
    assert_eq!(d.snapshot_seq, 1);
    assert_eq!(d.registry_snapshot_hash_hex.len(), 64);
}

// ── integrity of the record itself ─────────────────────────────────────────────

#[test]
fn json_roundtrip_preserves_digest_consistency() {
    let file = b"roundtrip";
    let bundle = seal_file("e.txt", file, None, &signer());
    let reg = authorizing_registry(&facts_of(&bundle));
    let e = SealEvidenceV1::from_result(
        &verify_sealed(&bundle, file, &reg),
        RuntimeContext::default(),
    );

    let json = e.to_json_pretty();
    let back: SealEvidenceV1 = serde_json::from_str(&json).expect("evidence JSON parses");
    assert_eq!(back, e);
    assert!(back.digest_consistent());
}

#[test]
fn digest_consistent_detects_edited_deterministic_section() {
    let file = b"tamper-the-record";
    let bundle = seal_file("e.txt", file, None, &signer());
    let e = SealEvidenceV1::from_result(
        &verify_sealed(&bundle, file, &empty_registry()),
        RuntimeContext::default(),
    );

    // Hand-edit the JSON: flip REJECT to ACCEPT without recomputing the digest.
    let mut v: serde_json::Value = serde_json::from_str(&e.to_json_pretty()).expect("json");
    v["deterministic"]["result"] = serde_json::Value::String("ACCEPT".to_string());
    let forged: SealEvidenceV1 = serde_json::from_value(v).expect("forged parses");
    assert!(
        !forged.digest_consistent(),
        "edited deterministic section must break the digest"
    );

    // Editing runtime fields, by contrast, stays consistent (they're outside the digest).
    let mut v2: serde_json::Value = serde_json::from_str(&e.to_json_pretty()).expect("json");
    v2["runtime"]["file_path"] = serde_json::Value::String("D:\\moved\\e.txt".to_string());
    let moved: SealEvidenceV1 = serde_json::from_value(v2).expect("parses");
    assert!(moved.digest_consistent());
}

// ── fixtures (same shapes as file_seal_verify.rs) ──────────────────────────────

fn signer() -> SoftwareProfileSigner {
    SoftwareProfileSigner::from_seed([0x42; 32], [0xC0; TE_DEVICE_ID16_LEN], 7)
}

fn facts_of(bundle: &SealedBundle) -> VerifiedFacts {
    let frame = hex::decode(&bundle.frame_hex).expect("frame hex");
    verified_facts_from_accepted_frame(&frame).expect("facts from a freshly sealed frame")
}

fn authorizing_registry(facts: &VerifiedFacts) -> Registry {
    Registry {
        snapshot_seq: 1,
        as_of_unix_ms: 1_700_000_000_000,
        policy_version: "evidence-registry-v0".to_string(),
        entries: vec![RegistryEntry {
            device_id16: facts.device_id16,
            device_id32: facts.device_id32,
            authorized_te_hashes: vec![facts.te_hash],
            current_epoch: facts.epoch,
            revoked: false,
            frozen: false,
            recovery_hold: false,
            policy_version: "evidence-device-v0".to_string(),
        }],
    }
}

fn empty_registry() -> Registry {
    Registry {
        snapshot_seq: 1,
        as_of_unix_ms: 1_700_000_000_000,
        policy_version: "evidence-registry-v0".to_string(),
        entries: vec![],
    }
}
