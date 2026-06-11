//! R2 policy-engine characterization tests — threat-model hardening (doc 04).
//!
//! Run:
//!   cargo test -p andna-r2 --locked --test r2_characterization
//!
//! Pins already-built behavior not covered by `policy_engine.rs`. Reconciled against that
//! suite — nothing here duplicates the existing 20+ tests. All tests are pure (no liboqs).
//!
//! Key findings pinned here (from doc 04):
//!   - Policy-version fields are informational; mismatch is recorded, not rejected.
//!   - R2 does not currently enforce a freshness floor on `as_of_unix_ms`.
//!   - Stale-snapshot warning test is marked ignored pending floor implementation.

use andna_contracts::{MU_PRE_DEVICE_ID32_LEN, PK_HASH_LEN, TE_DEVICE_ID16_LEN};
use andna_r2::{authorize, Registry, RegistryEntry, Stage1Outcome, VerifiedFacts};

fn facts() -> VerifiedFacts {
    VerifiedFacts {
        device_id16: [0x11; TE_DEVICE_ID16_LEN],
        device_id32: [0x22; MU_PRE_DEVICE_ID32_LEN],
        epoch: 5,
        te_hash: [0x33; PK_HASH_LEN],
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

// ── Policy-version mismatch (doc 04: "policy-version mismatch is recorded, not rejected") ──

/// R2 does not currently enforce version consistency between the registry's
/// `policy_version` and an entry's `policy_version`. Both versions are captured in
/// the policy digest, but a mismatch does not cause a rejection.
///
/// This pins the current behavior as "recorded, not rejected." If a version gate is
/// added later, this test will fail and must be updated to reflect the new behavior.
#[test]
fn policy_version_mismatch_is_recorded_not_rejected() {
    let f = facts();
    let mut e = entry_for(&f);
    e.policy_version = "device-policy-FUTURE-v99".to_string();
    let mut reg = registry_with(vec![e]);
    reg.policy_version = "andna-r2-registry-v0".to_string();

    let d = authorize(&Stage1Outcome::CryptoAccept(f), &reg);

    assert_eq!(
        d.stage2, "AUTHORIZED",
        "policy_version mismatch between registry and entry must not block authorization"
    );
    assert_eq!(d.reason, "registry_entry_valid");
    // The decision is captured in the policy digest (present and non-empty).
    assert!(
        d.policy_digest_hex.as_deref().map(|s| s.len()) == Some(64),
        "policy_digest_hex must be present for AUTHORIZED decision"
    );
}

/// Registry-level policy_version mismatch (different major schema) is also recorded,
/// not rejected. R2 treats policy_version as an audit field in the current implementation.
#[test]
fn registry_policy_version_is_informational() {
    let f = facts();
    let mut reg = registry_with(vec![entry_for(&f)]);
    reg.policy_version = "andna-r2-registry-LEGACY-v0".to_string();

    let d = authorize(&Stage1Outcome::CryptoAccept(f), &reg);

    assert_eq!(d.stage2, "AUTHORIZED");
    // snapshot_hash changes with registry_policy_version because the full registry
    // (including policy_version) is hashed. This is how the version is "recorded."
    assert_eq!(d.snapshot_hash_hex.len(), 64);
}

// ── Snapshot binding (characterizes the R2 evidence record) ───────────────────

/// R2 records snapshot_seq, as_of_unix_ms, and snapshot_hash in every decision.
/// These fields distinguish decisions made against different snapshots even when the
/// authorization outcome (AUTHORIZED / NOT_AUTHORIZED) is the same.
#[test]
fn snapshot_identity_fields_are_present_on_authorized_decision() {
    let f = facts();
    let reg = registry_with(vec![entry_for(&f)]);

    let d = authorize(&Stage1Outcome::CryptoAccept(f), &reg);

    assert_eq!(d.stage2, "AUTHORIZED");
    // snapshot_seq and as_of_unix_ms are bound into the decision:
    assert_eq!(d.snapshot_seq, 1);
    assert_eq!(d.as_of_unix_ms, 1_700_000_000_000);
    assert_eq!(d.snapshot_hash_hex.len(), 64);
}

/// R2 does not currently check whether `as_of_unix_ms` is within a freshness window.
/// An arbitrarily old snapshot (as_of_unix_ms = 0) still authorizes if the entry is valid.
/// This pins the absence of a freshness floor — the threat is documented in doc 04.
#[test]
fn ancient_snapshot_timestamp_does_not_block_authorization() {
    let f = facts();
    let mut reg = registry_with(vec![entry_for(&f)]);
    reg.as_of_unix_ms = 0; // epoch 0 — "ancient"

    let d = authorize(&Stage1Outcome::CryptoAccept(f), &reg);

    assert_eq!(
        d.stage2, "AUTHORIZED",
        "R2 does not currently enforce a freshness floor; ancient snapshot must still authorize"
    );
    assert_eq!(d.as_of_unix_ms, 0, "as_of_unix_ms = 0 is recorded faithfully");
}

// ── Not-yet-built: stale-snapshot warning ─────────────────────────────────────

/// Placeholder: activates once a freshness floor is implemented.
///
/// When R2 gains an `as_of_unix_ms` freshness window, this test should assert that
/// authorization against a snapshot older than the configured window emits a staleness
/// indicator or is refused. Do not implement the floor here — mark as ignored.
///
/// activates once freshness floor exists (not-yet-built, doc 04)
#[test]
#[ignore = "activates once as_of_unix_ms freshness floor exists (not-yet-built)"]
fn stale_snapshot_emits_staleness_indicator() {
    // When the freshness floor is added, replace this body with:
    //   let d = authorize(..., &stale_registry);
    //   assert!(d.staleness_flag, "stale snapshot must set a staleness indicator");
    // Do not add R2 freshness logic — this is a future mitigation documented in doc 04.
}
