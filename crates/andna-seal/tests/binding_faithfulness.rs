//! Binding-faithfulness differential — threat-model hardening finding F1.
//!
//! Run:
//!   cargo test -p andna-seal --test binding_faithfulness --locked
//!
//! Pins the load-bearing statement: the verifier's extracted `ctx_hash` is byte-identical to
//! the sealer's `manifest_hash` at the binding point, and deliberate perturbations of any
//! manifest field CHANGE the hash and break verification.
//!
//! Architecture note (F1 report): the verifier does NOT "reconstruct" ctx_hash. It EXTRACTS
//! the signed ctx_hash from the authenticated frame and compares against a freshly computed
//! manifest_hash. Both sides call the same `Manifest::manifest_hash()` → `canonical_bytes()`
//! → SHA3-256 path. This is the correct "capture the exact state" architecture — there is no
//! "equivalent re-derivation" seam to drift.
//!
//! RECONCILED against `file_seal_verify.rs`:
//!   - `seal_then_verify_authorized` asserts ctx_hash == manifest_hash (positive);
//!   - `verify_rejects_tampered_manifest` flips file_name only.
//! This file adds the DIFFERENTIAL: multiple independent perturbations, each proven to change
//! the hash AND break unchanged-binding, plus the positive control as a precondition gate.

use andna_contracts::TE_DEVICE_ID16_LEN;
use andna_pipeline::{verified_facts_from_accepted_frame, Registry, RegistryEntry, VerifiedFacts};
use andna_seal::{seal_file, verify_sealed, SealedBundle, SoftwareProfileSigner, Verdict};

fn signer() -> SoftwareProfileSigner {
    SoftwareProfileSigner::from_seed([0x42; 32], [0xC0; TE_DEVICE_ID16_LEN], 7)
}

fn facts_of(bundle: &SealedBundle) -> VerifiedFacts {
    let frame = hex::decode(&bundle.frame_hex).expect("frame hex");
    verified_facts_from_accepted_frame(&frame).expect("facts from frame")
}

fn authorizing_registry(facts: &VerifiedFacts) -> Registry {
    Registry {
        snapshot_seq: 1,
        as_of_unix_ms: 1_700_000_000_000,
        policy_version: "binding-test-registry-v0".to_string(),
        entries: vec![RegistryEntry {
            device_id16: facts.device_id16,
            device_id32: facts.device_id32,
            authorized_te_hashes: vec![facts.te_hash],
            current_epoch: facts.epoch,
            revoked: false,
            frozen: false,
            recovery_hold: false,
            policy_version: "binding-test-device-v0".to_string(),
        }],
    }
}

/// Positive control gate: the honest path must pass FIRST. If this fails, every subsequent
/// differential result is inconclusive (F6 principle: positive control before classification).
#[test]
fn positive_control_honest_path_binds() {
    let file = b"binding faithfulness test content";
    let bundle = seal_file("faithful.bin", file, None, &signer());
    let reg = authorizing_registry(&facts_of(&bundle));

    let r = verify_sealed(&bundle, file, &reg);
    assert!(
        r.authentic,
        "positive control: R1 must accept the honest frame"
    );
    assert_eq!(
        r.unchanged,
        Verdict::Yes,
        "positive control: binding must hold on the honest path"
    );
    assert_eq!(
        r.frame_ctx_hash_hex, r.computed_manifest_hash_hex,
        "positive control: ctx_hash extracted from signed frame must be byte-identical \
         to the freshly computed manifest_hash"
    );
    assert!(
        r.overall_accept,
        "positive control: overall verdict must be ACCEPT"
    );
}

/// Perturbation: changing `file_name` in the manifest changes `manifest_hash` and breaks the
/// ctx_hash binding (manifest_hash_mismatch). The frame is untouched so R1 still accepts.
#[test]
fn perturbation_file_name_breaks_binding() {
    let file = b"binding faithfulness test content";
    let mut bundle = seal_file("faithful.bin", file, None, &signer());
    let reg = authorizing_registry(&facts_of(&bundle));

    bundle.manifest.file_name = "renamed.bin".to_string();

    let r = verify_sealed(&bundle, file, &reg);
    assert!(r.authentic, "frame untouched: R1 must still accept");
    assert_eq!(r.unchanged, Verdict::No);
    assert_eq!(
        r.unchanged_detail.as_deref(),
        Some("manifest_hash_mismatch")
    );
    assert_ne!(
        r.frame_ctx_hash_hex, r.computed_manifest_hash_hex,
        "perturbed file_name must produce a different manifest_hash than the signed ctx_hash"
    );
}

/// Perturbation: changing `schema_version` in the manifest changes `manifest_hash` and breaks
/// binding. This field is absorbed early in `canonical_bytes()` — proves the binding includes
/// structural metadata, not just file content.
#[test]
fn perturbation_schema_version_breaks_binding() {
    let file = b"binding faithfulness test content";
    let mut bundle = seal_file("faithful.bin", file, None, &signer());
    let reg = authorizing_registry(&facts_of(&bundle));

    bundle.manifest.schema_version = "andna-seal-manifest-v999".to_string();

    let r = verify_sealed(&bundle, file, &reg);
    assert!(r.authentic, "frame untouched: R1 must still accept");
    assert_eq!(r.unchanged, Verdict::No);
    assert_eq!(
        r.unchanged_detail.as_deref(),
        Some("manifest_hash_mismatch")
    );
}

/// Perturbation: changing `manifest_policy` in the manifest changes `manifest_hash` and breaks
/// binding. Policy is absorbed in `canonical_bytes()` — proves the binding covers the policy
/// field, not just content hashes.
#[test]
fn perturbation_manifest_policy_breaks_binding() {
    let file = b"binding faithfulness test content";
    let mut bundle = seal_file("faithful.bin", file, None, &signer());
    let reg = authorizing_registry(&facts_of(&bundle));

    bundle.manifest.manifest_policy = "evil-policy-v0".to_string();

    let r = verify_sealed(&bundle, file, &reg);
    assert!(r.authentic, "frame untouched: R1 must still accept");
    assert_eq!(r.unchanged, Verdict::No);
    assert_eq!(
        r.unchanged_detail.as_deref(),
        Some("manifest_hash_mismatch")
    );
}

/// Perturbation: changing `digest_algorithm` breaks binding even though the declared file hash
/// bytes haven't changed. The algorithm string is absorbed in `canonical_bytes()`.
#[test]
fn perturbation_digest_algorithm_breaks_binding() {
    let file = b"binding faithfulness test content";
    let mut bundle = seal_file("faithful.bin", file, None, &signer());
    let reg = authorizing_registry(&facts_of(&bundle));

    bundle.manifest.digest_algorithm = "sha3-512".to_string();

    let r = verify_sealed(&bundle, file, &reg);
    assert!(r.authentic, "frame untouched: R1 must still accept");
    assert_eq!(r.unchanged, Verdict::No);
    assert_eq!(
        r.unchanged_detail.as_deref(),
        Some("manifest_hash_mismatch")
    );
}

/// Perturbation: changing `content_type` from None to Some breaks binding. The optional field
/// is absorbed (as empty string when None) in `canonical_bytes()`.
#[test]
fn perturbation_content_type_breaks_binding() {
    let file = b"binding faithfulness test content";
    let mut bundle = seal_file("faithful.bin", file, None, &signer());
    let reg = authorizing_registry(&facts_of(&bundle));

    bundle.manifest.content_type = Some("application/evil".to_string());

    let r = verify_sealed(&bundle, file, &reg);
    assert!(r.authentic, "frame untouched: R1 must still accept");
    assert_eq!(r.unchanged, Verdict::No);
    assert_eq!(
        r.unchanged_detail.as_deref(),
        Some("manifest_hash_mismatch")
    );
}

/// Perturbation: changing `file_size` in the manifest breaks binding even though the actual
/// file bytes haven't changed. Size is absorbed as u64 LE in `canonical_bytes()` — proves
/// the binding includes the declared size, not just the hash.
#[test]
fn perturbation_file_size_breaks_binding() {
    let file = b"binding faithfulness test content";
    let mut bundle = seal_file("faithful.bin", file, None, &signer());
    let reg = authorizing_registry(&facts_of(&bundle));

    bundle.manifest.file_size += 1;

    let r = verify_sealed(&bundle, file, &reg);
    assert!(r.authentic, "frame untouched: R1 must still accept");
    assert_eq!(r.unchanged, Verdict::No);
    assert_eq!(
        r.unchanged_detail.as_deref(),
        Some("manifest_hash_mismatch")
    );
}

/// Differential: all seven manifest fields are independently bound. Each perturbation above
/// changes manifest_hash in a DISTINCT way (no two produce the same perturbed hash), proving
/// every field contributes to the binding — none are dead weight.
#[test]
fn all_manifest_fields_produce_distinct_hashes() {
    use andna_seal::Manifest;

    let base = Manifest::for_file("faithful.bin", b"binding faithfulness test content", None);
    let base_hash = base.manifest_hash();

    let perturbations: Vec<Manifest> = vec![
        {
            let mut m = base.clone();
            m.file_name = "other.bin".to_string();
            m
        },
        {
            let mut m = base.clone();
            m.schema_version = "v999".to_string();
            m
        },
        {
            let mut m = base.clone();
            m.manifest_policy = "other-policy".to_string();
            m
        },
        {
            let mut m = base.clone();
            m.digest_algorithm = "sha3-512".to_string();
            m
        },
        {
            let mut m = base.clone();
            m.content_type = Some("text/evil".to_string());
            m
        },
        {
            let mut m = base.clone();
            m.file_size += 1;
            m
        },
        {
            let mut m = base.clone();
            m.file_hash_hex = hex::encode([0xFFu8; 32]);
            m
        },
    ];

    let mut hashes: Vec<[u8; 32]> = perturbations.iter().map(|m| m.manifest_hash()).collect();
    for h in &hashes {
        assert_ne!(h, &base_hash, "every perturbation must differ from base");
    }
    hashes.sort();
    hashes.dedup();
    assert_eq!(
        hashes.len(),
        perturbations.len(),
        "all perturbations must produce DISTINCT hashes (no two fields collide)"
    );
}
