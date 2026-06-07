//! R2 policy-engine tests.
//!
//! Pure: no liboqs, no R1. These tests exercise the decision logic and
//! `policy_digest` directly. The fixtures match the shipped
//! `sample/local_registry.json`, so the sample is validated as a side effect.

use andna_contracts::{MU_PRE_DEVICE_ID32_LEN, PK_HASH_LEN, TE_DEVICE_ID16_LEN};
use andna_r2::{authorize, Registry, RegistryEntry, RegistryError, Stage1Outcome, VerifiedFacts};

const SAMPLE_JSON: &str = include_str!("../sample/local_registry.json");

fn sample_facts() -> VerifiedFacts {
    VerifiedFacts {
        device_id16: [0x11; TE_DEVICE_ID16_LEN],
        device_id32: [0x22; MU_PRE_DEVICE_ID32_LEN],
        epoch: 7,
        te_hash: [0x33; PK_HASH_LEN],
    }
}

fn second_facts() -> VerifiedFacts {
    VerifiedFacts {
        device_id16: [0x44; TE_DEVICE_ID16_LEN],
        device_id32: [0x55; MU_PRE_DEVICE_ID32_LEN],
        epoch: 9,
        te_hash: [0x66; PK_HASH_LEN],
    }
}

fn entry_for(f: &VerifiedFacts) -> RegistryEntry {
    RegistryEntry {
        device_id16: f.device_id16,
        device_id32: f.device_id32,
        authorized_te_hashes: vec![f.te_hash],
        current_epoch: f.epoch,
        revoked: false,
        frozen: false,
        recovery_hold: false,
        policy_version: "device-policy-v0".to_string(),
    }
}

fn registry_with(entries: Vec<RegistryEntry>) -> Registry {
    Registry {
        snapshot_seq: 1,
        as_of_unix_ms: 1_700_000_000_000,
        policy_version: "andna-r2-registry-v0".to_string(),
        entries,
    }
}

// ── positive ─────────────────────────────────────────────────────────────────

#[test]
fn authorized_when_entry_valid() {
    let f = sample_facts();
    let reg = registry_with(vec![entry_for(&f)]);
    let d = authorize(&Stage1Outcome::CryptoAccept(f), &reg);

    assert_eq!(d.stage1, "CRYPTO_ACCEPT");
    assert_eq!(d.stage2, "AUTHORIZED");
    assert_eq!(d.reason, "registry_entry_valid");
    assert_eq!(d.attestation_status, "NONE_SOFTWARE_PROFILE");
    assert_eq!(d.policy_digest_hex.as_deref().unwrap().len(), 64);
    assert_eq!(d.snapshot_hash_hex.len(), 64);
}

// ── fail-closed: R1 reject never evaluates policy ─────────────────────────────

#[test]
fn not_evaluated_when_stage1_reject() {
    let reg = registry_with(vec![]);
    let d = authorize(&Stage1Outcome::CryptoReject, &reg);

    assert_eq!(d.stage1, "CRYPTO_REJECT");
    assert_eq!(d.stage2, "NOT_EVALUATED");
    assert_eq!(d.reason, "stage1_reject");
    assert_eq!(d.policy_digest_hex, None);

    assert_eq!(d.device_id32_hex, "00".repeat(MU_PRE_DEVICE_ID32_LEN));
    assert_eq!(d.epoch, 0);
    assert_eq!(d.te_hash_hex, "00".repeat(PK_HASH_LEN));
}

// ── negatives, one directive each ─────────────────────────────────────────────

#[test]
fn not_authorized_when_no_entry() {
    let f = sample_facts();
    let reg = registry_with(vec![]);
    let d = authorize(&Stage1Outcome::CryptoAccept(f), &reg);

    assert_eq!(d.stage2, "NOT_AUTHORIZED");
    assert_eq!(d.reason, "no_registry_entry");
}

#[test]
fn not_authorized_when_device_id16_mismatch() {
    let f = sample_facts();
    let mut e = entry_for(&f);
    e.device_id16 = [0x44; TE_DEVICE_ID16_LEN];

    let d = authorize(&Stage1Outcome::CryptoAccept(f), &registry_with(vec![e]));

    assert_eq!(d.stage2, "NOT_AUTHORIZED");
    assert_eq!(d.reason, "device_id16_mismatch");
}

#[test]
fn not_authorized_when_revoked() {
    let f = sample_facts();
    let mut e = entry_for(&f);
    e.revoked = true;

    let d = authorize(&Stage1Outcome::CryptoAccept(f), &registry_with(vec![e]));

    assert_eq!(d.stage2, "NOT_AUTHORIZED");
    assert_eq!(d.reason, "device_revoked");
}

#[test]
fn not_authorized_when_frozen() {
    let f = sample_facts();
    let mut e = entry_for(&f);
    e.frozen = true;

    let d = authorize(&Stage1Outcome::CryptoAccept(f), &registry_with(vec![e]));

    assert_eq!(d.stage2, "NOT_AUTHORIZED");
    assert_eq!(d.reason, "lineage_frozen");
}

#[test]
fn not_authorized_when_recovery_hold() {
    let f = sample_facts();
    let mut e = entry_for(&f);
    e.recovery_hold = true;

    let d = authorize(&Stage1Outcome::CryptoAccept(f), &registry_with(vec![e]));

    assert_eq!(d.stage2, "NOT_AUTHORIZED");
    assert_eq!(d.reason, "recovery_hold");
}

#[test]
fn not_authorized_when_epoch_stale() {
    let f = sample_facts();
    let mut e = entry_for(&f);
    e.current_epoch = f.epoch + 1;

    let d = authorize(&Stage1Outcome::CryptoAccept(f), &registry_with(vec![e]));

    assert_eq!(d.stage2, "NOT_AUTHORIZED");
    assert_eq!(d.reason, "epoch_stale");
}

#[test]
fn not_authorized_when_te_not_listed() {
    let f = sample_facts();
    let mut e = entry_for(&f);
    e.authorized_te_hashes = vec![[0x99; PK_HASH_LEN]];

    let d = authorize(&Stage1Outcome::CryptoAccept(f), &registry_with(vec![e]));

    assert_eq!(d.stage2, "NOT_AUTHORIZED");
    assert_eq!(d.reason, "te_not_authorized");
}

// ── severity precedence ──────────────────────────────────────────────────────

#[test]
fn revoked_takes_precedence_over_other_failures() {
    let f = sample_facts();
    let mut e = entry_for(&f);

    e.revoked = true;
    e.current_epoch = f.epoch + 5;
    e.authorized_te_hashes = vec![[0x99; PK_HASH_LEN]];

    let d = authorize(&Stage1Outcome::CryptoAccept(f), &registry_with(vec![e]));

    assert_eq!(d.stage2, "NOT_AUTHORIZED");
    assert_eq!(d.reason, "device_revoked");
}

// ── policy_digest properties ─────────────────────────────────────────────────

#[test]
fn policy_digest_is_deterministic() {
    let f = sample_facts();
    let reg = registry_with(vec![entry_for(&f)]);

    let d1 = authorize(&Stage1Outcome::CryptoAccept(f.clone()), &reg);
    let d2 = authorize(&Stage1Outcome::CryptoAccept(f), &reg);

    assert_eq!(d1.policy_digest_hex, d2.policy_digest_hex);
}

#[test]
fn policy_digest_changes_with_decision() {
    let f = sample_facts();

    let reg_ok = registry_with(vec![entry_for(&f)]);

    let mut bad = entry_for(&f);
    bad.revoked = true;
    let reg_bad = registry_with(vec![bad]);

    let ok = authorize(&Stage1Outcome::CryptoAccept(f.clone()), &reg_ok);
    let no = authorize(&Stage1Outcome::CryptoAccept(f), &reg_bad);

    assert_eq!(ok.stage2, "AUTHORIZED");
    assert_eq!(no.stage2, "NOT_AUTHORIZED");
    assert_ne!(ok.policy_digest_hex, no.policy_digest_hex);
}

#[test]
fn policy_digest_binds_snapshot_even_for_same_decision() {
    let f = sample_facts();

    let reg1 = registry_with(vec![entry_for(&f)]);

    let mut reg2 = registry_with(vec![entry_for(&f)]);
    reg2.snapshot_seq = 2;

    let d1 = authorize(&Stage1Outcome::CryptoAccept(f.clone()), &reg1);
    let d2 = authorize(&Stage1Outcome::CryptoAccept(f), &reg2);

    assert_eq!(d1.stage2, d2.stage2);
    assert_ne!(d1.policy_digest_hex, d2.policy_digest_hex);
    assert_ne!(d1.snapshot_hash_hex, d2.snapshot_hash_hex);
}

#[test]
fn snapshot_hash_is_independent_of_entry_order() {
    let f1 = sample_facts();
    let f2 = second_facts();

    let reg1 = registry_with(vec![entry_for(&f1), entry_for(&f2)]);
    let reg2 = registry_with(vec![entry_for(&f2), entry_for(&f1)]);

    assert_eq!(reg1.snapshot_hash(), reg2.snapshot_hash());
}

#[test]
fn snapshot_hash_is_independent_of_authorized_te_hash_order() {
    let f = sample_facts();

    let mut e1 = entry_for(&f);
    e1.authorized_te_hashes = vec![[0x01; PK_HASH_LEN], f.te_hash, [0x02; PK_HASH_LEN]];

    let mut e2 = entry_for(&f);
    e2.authorized_te_hashes = vec![[0x02; PK_HASH_LEN], f.te_hash, [0x01; PK_HASH_LEN]];

    let reg1 = registry_with(vec![e1]);
    let reg2 = registry_with(vec![e2]);

    assert_eq!(reg1.snapshot_hash(), reg2.snapshot_hash());
}

// ── validated registry load ──────────────────────────────────────────────────

#[test]
fn sample_registry_loads_and_authorizes_known_device() {
    let reg = Registry::from_json(SAMPLE_JSON).expect("sample registry must load");

    assert_eq!(reg.policy_version, "andna-r2-registry-v0");
    assert_eq!(reg.entries.len(), 1);

    let d = authorize(&Stage1Outcome::CryptoAccept(sample_facts()), &reg);

    assert_eq!(d.stage2, "AUTHORIZED");
    assert_eq!(d.reason, "registry_entry_valid");
}

#[test]
fn registry_load_rejects_bad_hex_width() {
    let bad = r#"{
        "snapshot_seq": 1,
        "as_of_unix_ms": 0,
        "policy_version": "x",
        "entries": [{
            "device_id16_hex": "1122",
            "device_id32_hex": "2222222222222222222222222222222222222222222222222222222222222222",
            "authorized_te_hashes_hex": [],
            "current_epoch": 0,
            "policy_version": "y"
        }]
    }"#;

    match Registry::from_json(bad) {
        Err(RegistryError::BadWidth {
            field,
            expected,
            got,
        }) => {
            assert_eq!(field, "device_id16_hex");
            assert_eq!(expected, TE_DEVICE_ID16_LEN);
            assert_eq!(got, 2);
        }
        other => panic!("expected BadWidth, got {other:?}"),
    }
}

#[test]
fn registry_load_rejects_non_hex() {
    let bad = r#"{
        "snapshot_seq": 1,
        "as_of_unix_ms": 0,
        "policy_version": "x",
        "entries": [{
            "device_id16_hex": "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",
            "device_id32_hex": "2222222222222222222222222222222222222222222222222222222222222222",
            "authorized_te_hashes_hex": [],
            "current_epoch": 0,
            "policy_version": "y"
        }]
    }"#;

    assert!(matches!(
        Registry::from_json(bad),
        Err(RegistryError::HexField {
            field: "device_id16_hex",
            ..
        })
    ));
}

#[test]
fn registry_load_rejects_duplicate_device_id32() {
    let bad = r#"{
        "snapshot_seq": 1,
        "as_of_unix_ms": 0,
        "policy_version": "x",
        "entries": [
          {
            "device_id16_hex": "11111111111111111111111111111111",
            "device_id32_hex": "2222222222222222222222222222222222222222222222222222222222222222",
            "authorized_te_hashes_hex": [],
            "current_epoch": 0,
            "policy_version": "a"
          },
          {
            "device_id16_hex": "33333333333333333333333333333333",
            "device_id32_hex": "2222222222222222222222222222222222222222222222222222222222222222",
            "authorized_te_hashes_hex": [],
            "current_epoch": 0,
            "policy_version": "b"
          }
        ]
    }"#;

    assert!(matches!(
        Registry::from_json(bad),
        Err(RegistryError::DuplicateDevice { .. })
    ));
}
