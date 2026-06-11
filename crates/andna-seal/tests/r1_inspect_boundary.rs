//! R1 verifier boundary characterization tests — threat-model hardening (doc 03).
//!
//! Run:
//!   cargo test -p andna-seal --test r1_inspect_boundary -- --nocapture
//!
//! Pins the boundary: `inspect-seal` (sidecar parse) carries no verdict.
//! Only `verify_sealed` + a registry snapshot can produce an ACCEPT decision.
//! This test is RECONCILED against the existing suite in `file_seal_verify.rs` —
//! it does not duplicate the tamper/reject matrix already covered there.

use andna_contracts::TE_DEVICE_ID16_LEN;
use andna_pipeline::{Registry, RegistryEntry, VerifiedFacts, verified_facts_from_accepted_frame};
use andna_seal::{seal_file, verify_sealed, SealedBundle, SoftwareProfileSigner, Verdict};

fn signer() -> SoftwareProfileSigner {
    SoftwareProfileSigner::from_seed([0x55; 32], [0xAA; TE_DEVICE_ID16_LEN], 3)
}

fn authorizing_registry(facts: &VerifiedFacts) -> Registry {
    Registry {
        snapshot_seq: 1,
        as_of_unix_ms: 1_700_000_000_000,
        policy_version: "r1-boundary-registry-v0".to_string(),
        entries: vec![RegistryEntry {
            device_id16: facts.device_id16,
            device_id32: facts.device_id32,
            authorized_te_hashes: vec![facts.te_hash],
            current_epoch: facts.epoch,
            revoked: false,
            frozen: false,
            recovery_hold: false,
            policy_version: "r1-boundary-device-v0".to_string(),
        }],
    }
}

fn empty_registry() -> Registry {
    Registry {
        snapshot_seq: 1,
        as_of_unix_ms: 1_700_000_000_000,
        policy_version: "r1-boundary-registry-v0".to_string(),
        entries: vec![],
    }
}

/// Parsing (inspecting) a sealed bundle does not produce a verdict.
///
/// A `SealedBundle` is a structural representation of the sidecar — it exposes the
/// frame hex, manifest fields, schema version, and frame encoding, but carries no
/// `authentic`, `unchanged`, `authorized`, or `overall_accept` state. A verdict requires
/// calling `verify_sealed` with the original file bytes and a registry snapshot.
///
/// This pins the boundary stated in doc 03: `inspect-seal` structural pass does not
/// imply ACCEPT. It takes an authorizing registry to confirm that the SAME bundle,
/// with the correct inputs, produces ACCEPT — making the contrast explicit.
#[test]
fn sidecar_structural_parse_carries_no_verdict() {
    let file = b"inspect boundary test file";
    let bundle = seal_file("boundary.txt", file, None, &signer());

    // Structural fields accessible from the parsed bundle (the "inspect" layer):
    assert_eq!(bundle.schema_version, "andna-seal-sidecar-v0");
    assert!(!bundle.frame_hex.is_empty(), "frame_hex must be non-empty");
    assert_eq!(bundle.frame_encoding, "frame-v2-hex");
    assert_eq!(bundle.manifest.file_name, "boundary.txt");
    // The bundle itself carries no verdict field — there is no bundle.authentic,
    // bundle.authorized, or bundle.overall_accept. Inspection alone is not a decision.

    // Confirm that the SAME bundle + correct inputs + authorizing registry → ACCEPT.
    let frame = hex::decode(&bundle.frame_hex).expect("frame hex");
    let facts = verified_facts_from_accepted_frame(&frame).expect("facts from fresh frame");
    let auth_reg = authorizing_registry(&facts);
    let accept = verify_sealed(&bundle, file, &auth_reg);
    assert!(
        accept.overall_accept,
        "same bundle with correct inputs and authorizing registry must ACCEPT"
    );

    // And the SAME bundle without a registry entry → NOT AUTHORIZED (not ACCEPT).
    // This is the `inspect-seal cannot imply ACCEPT` assertion:
    // structural correctness of the sidecar does not establish authorization.
    let inspect_only = verify_sealed(&bundle, file, &empty_registry());
    assert!(
        inspect_only.authentic,
        "frame must be authentic (R1 passes; the crypto is valid)"
    );
    assert_eq!(
        inspect_only.unchanged,
        Verdict::Yes,
        "file is unchanged"
    );
    assert_eq!(
        inspect_only.authorized,
        Verdict::No,
        "inspect-level pass (valid frame, unchanged file) does NOT imply authorized"
    );
    assert!(
        !inspect_only.overall_accept,
        "inspect-level pass must NOT produce ACCEPT without an authorizing registry"
    );
}

/// A tampered sidecar (frame byte flip) causes authentic=false and short-circuits both
/// UNCHANGED and AUTHORIZED evaluation. This is a companion assertion to the inspect
/// boundary: even if the sidecar structure parses cleanly at the JSON level, a
/// corrupted frame byte is caught by R1 before any authorization check runs.
#[test]
fn tampered_frame_is_not_rescued_by_matching_registry() {
    use andna_contracts::FRAME_V2_SIG_OFF;

    let file = b"tamper boundary test";
    let bundle = seal_file("tamper.txt", file, None, &signer());
    let frame = hex::decode(&bundle.frame_hex).expect("frame hex");
    let facts = verified_facts_from_accepted_frame(&frame).expect("facts");
    let auth_reg = authorizing_registry(&facts);

    // Flip a signature byte — the sidecar JSON still parses (inspect succeeds at JSON),
    // but R1 rejects the frame.
    let mut tampered_frame = frame.clone();
    tampered_frame[FRAME_V2_SIG_OFF] ^= 0xFF;
    let mut tampered = bundle.clone();
    tampered.frame_hex = hex::encode(&tampered_frame);

    let result = verify_sealed(&tampered, file, &auth_reg);
    assert!(
        !result.authentic,
        "tampered frame must not be authentic"
    );
    assert_eq!(
        result.unchanged,
        Verdict::NotEvaluated,
        "unchanged is not evaluated when R1 rejects"
    );
    assert_eq!(
        result.authorized,
        Verdict::NotEvaluated,
        "authorized is not evaluated when R1 rejects — fail-closed"
    );
    assert!(
        !result.overall_accept,
        "even an authorizing registry cannot rescue a tampered frame"
    );
}
