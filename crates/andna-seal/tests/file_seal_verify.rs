//! andna-seal end-to-end matrix (gated on `oqs-backend`; verification calls the real R1).
//!
//! Run:
//!   cargo test -p andna-seal --test file_seal_verify -- --nocapture
//!
//! Proves the seal/verify chain and isolates each failure mode:
//!   tampered file     -> UNCHANGED no (file_hash_mismatch)
//!   tampered manifest -> UNCHANGED no (manifest_hash_mismatch)
//!   tampered frame    -> AUTHENTIC no  (R1 reject; UNCHANGED/AUTHORIZED not evaluated)
//!   unknown device    -> AUTHORIZED no (R2 no_registry_entry)
//! plus manifest-hash determinism and sensitivity to file content / size / name.

use andna_contracts::{FRAME_V2_SIG_OFF, TE_DEVICE_ID16_LEN};
use andna_pipeline::{verified_facts_from_accepted_frame, Registry, RegistryEntry, VerifiedFacts};
use andna_seal::{
    seal_file, verify_sealed, Manifest, SealedBundle, SoftwareProfileSigner, Verdict,
};

// ── seal + verify ──────────────────────────────────────────────────────────────

#[test]
fn seal_then_verify_authorized() {
    let file = b"the quick brown fox";
    let bundle = seal_file("fox.txt", file, Some("text/plain".to_string()), &signer());
    let reg = authorizing_registry(&facts_of(&bundle));

    let r = verify_sealed(&bundle, file, &reg);
    assert!(r.authentic);
    assert_eq!(r.unchanged, Verdict::Yes);
    assert_eq!(r.authorized, Verdict::Yes);
    assert!(r.overall_accept);
    assert_eq!(
        r.summary(),
        "AUTHENTIC: yes | UNCHANGED: yes | AUTHORIZED: yes"
    );
    // Frame ctx_hash equals the manifest hash that was bound.
    assert_eq!(r.frame_ctx_hash_hex, r.computed_manifest_hash_hex);
}

#[test]
fn verify_rejects_tampered_file() {
    let file = b"original content";
    let bundle = seal_file("a.txt", file, None, &signer());
    let reg = authorizing_registry(&facts_of(&bundle));

    let tampered = b"original content!"; // different bytes
    let r = verify_sealed(&bundle, tampered, &reg);
    assert!(r.authentic); // frame intact
    assert_eq!(r.unchanged, Verdict::No);
    assert_eq!(r.unchanged_detail.as_deref(), Some("file_hash_mismatch"));
    assert!(!r.overall_accept);
}

#[test]
fn verify_rejects_tampered_manifest() {
    let file = b"payload";
    let mut bundle = seal_file("a.txt", file, None, &signer());
    let reg = authorizing_registry(&facts_of(&bundle)); // facts captured before tamper

    bundle.manifest.file_name = "evil.txt".to_string(); // not re-signed

    let r = verify_sealed(&bundle, file, &reg);
    assert!(r.authentic); // frame untouched
    assert_eq!(r.unchanged, Verdict::No);
    assert_eq!(
        r.unchanged_detail.as_deref(),
        Some("manifest_hash_mismatch")
    );
    assert!(!r.overall_accept);
}

#[test]
fn verify_rejects_tampered_frame() {
    let file = b"payload";
    let bundle = seal_file("a.txt", file, None, &signer());
    let reg = authorizing_registry(&facts_of(&bundle));

    let mut frame = hex::decode(&bundle.frame_hex).expect("frame hex");
    frame[FRAME_V2_SIG_OFF] ^= 0xFF; // break the signature
    let mut tampered = bundle.clone();
    tampered.frame_hex = hex::encode(&frame);

    let r = verify_sealed(&tampered, file, &reg);
    assert!(!r.authentic);
    assert_eq!(r.unchanged, Verdict::NotEvaluated);
    assert_eq!(r.authorized, Verdict::NotEvaluated);
    assert!(!r.overall_accept);
}

#[test]
fn verify_returns_not_authorized_for_unknown_device() {
    let file = b"payload";
    let bundle = seal_file("a.txt", file, None, &signer());

    let r = verify_sealed(&bundle, file, &empty_registry());
    assert!(r.authentic); // crypto + file are fine
    assert_eq!(r.unchanged, Verdict::Yes);
    assert_eq!(r.authorized, Verdict::No); // identity not in the registry
    assert!(!r.overall_accept);
}

// ── manifest hash properties ────────────────────────────────────────────────────

#[test]
fn manifest_hash_is_deterministic() {
    let m1 = Manifest::for_file("a.txt", b"abc", None);
    let m2 = Manifest::for_file("a.txt", b"abc", None);
    assert_eq!(m1.manifest_hash(), m2.manifest_hash());
}

#[test]
fn manifest_hash_changes_when_file_hash_changes() {
    let m1 = Manifest::for_file("a.txt", b"abc", None);
    let m2 = Manifest::for_file("a.txt", b"abd", None); // same length, different content
    assert_ne!(m1.file_hash_hex, m2.file_hash_hex);
    assert_ne!(m1.manifest_hash(), m2.manifest_hash());
}

#[test]
fn manifest_hash_changes_when_file_size_changes() {
    // Isolate size: identical declared file hash, different declared size.
    let base = Manifest::for_file("a.txt", b"abc", None);
    let mut bigger = base.clone();
    bigger.file_size = base.file_size + 1;
    assert_ne!(base.manifest_hash(), bigger.manifest_hash());
}

#[test]
fn manifest_hash_changes_when_file_name_changes() {
    // "renamed file behavior is explicit": file_name is bound into the seal, so a rename
    // recorded in the manifest breaks the binding.
    let a = Manifest::for_file("a.txt", b"abc", None);
    let mut renamed = a.clone();
    renamed.file_name = "b.txt".to_string();
    assert_ne!(a.manifest_hash(), renamed.manifest_hash());
}

// ── fixtures ─────────────────────────────────────────────────────────────────────

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
        policy_version: "seal-e2e-registry-v0".to_string(),
        entries: vec![RegistryEntry {
            device_id16: facts.device_id16,
            device_id32: facts.device_id32,
            authorized_te_hashes: vec![facts.te_hash],
            current_epoch: facts.epoch,
            revoked: false,
            frozen: false,
            recovery_hold: false,
            policy_version: "seal-device-v0".to_string(),
        }],
    }
}

fn empty_registry() -> Registry {
    Registry {
        snapshot_seq: 1,
        as_of_unix_ms: 1_700_000_000_000,
        policy_version: "seal-e2e-registry-v0".to_string(),
        entries: vec![],
    }
}
