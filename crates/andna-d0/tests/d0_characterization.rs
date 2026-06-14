//! D0 characterization tests — threat-model hardening (doc 02).
//!
//! Run:
//!   cargo test -p andna-d0 --locked --test d0_characterization
//!
//! These tests pin ALREADY-BUILT deterministic behavior via the public API only.
//! They are RECONCILED against the existing inline tests in `src/derive.rs` — nothing
//! here duplicates `vectors_match_spec_v0_3`, `ratchet_decorrelates_high_bits`,
//! `from_coeffs_enforces_range`, `record_length_and_field_validation`, or
//! `deterministic_healing_guard`.
//!
//! Connected-healing remains INACTIVE. No test here calls `ratchet_internal` with
//! non-zero healing, and the `d0-connected-healing` feature is never enabled.

use andna_d0::{
    check_deterministic_healing, ratchet_deterministic, D0Error, SecretState, D0_HEALING_SLOT_LEN,
    D0_P_N, EPOCH_SEED_DOMAIN, MLDSA_SEED_DOMAIN, RATCHET_STATE_DOMAIN,
};

// ── Domain labels ─────────────────────────────────────────────────────────────

/// All three D0 SHAKE256 domain labels are distinct and carry the `-v1` version suffix.
/// This characterizes the "domain separation SATISFIED" finding in doc 02.
#[test]
fn domain_labels_are_distinct_and_v1_suffixed() {
    assert_ne!(
        EPOCH_SEED_DOMAIN, MLDSA_SEED_DOMAIN,
        "epoch-seed and mldsa-seed labels must differ"
    );
    assert_ne!(
        EPOCH_SEED_DOMAIN, RATCHET_STATE_DOMAIN,
        "epoch-seed and ratchet-state labels must differ"
    );
    assert_ne!(
        MLDSA_SEED_DOMAIN, RATCHET_STATE_DOMAIN,
        "mldsa-seed and ratchet-state labels must differ"
    );

    assert!(
        EPOCH_SEED_DOMAIN.ends_with(b"-v1"),
        "EPOCH_SEED_DOMAIN must end with `-v1`"
    );
    assert!(
        MLDSA_SEED_DOMAIN.ends_with(b"-v1"),
        "MLDSA_SEED_DOMAIN must end with `-v1`"
    );
    assert!(
        RATCHET_STATE_DOMAIN.ends_with(b"-v1"),
        "RATCHET_STATE_DOMAIN must end with `-v1`"
    );
}

// ── Healing guard: multiple non-zero patterns ─────────────────────────────────

/// `check_deterministic_healing` rejects a variety of non-zero patterns, not only
/// `h[0] = 1`. The existing inline test (`deterministic_healing_guard`) covers the
/// first-byte case; this test adds coverage of middle byte, last byte, all-ones, and
/// alternating patterns. All must return `HealingNonzeroInDeterministicMode`.
#[test]
fn healing_guard_rejects_multiple_nonzero_patterns() {
    let zero = [0u8; D0_HEALING_SLOT_LEN];
    assert_eq!(check_deterministic_healing(&zero), Ok(()));

    let patterns: &[(&str, fn() -> [u8; D0_HEALING_SLOT_LEN])] = &[
        ("last byte set", || {
            let mut h = [0u8; D0_HEALING_SLOT_LEN];
            h[D0_HEALING_SLOT_LEN - 1] = 0xFF;
            h
        }),
        ("middle byte set", || {
            let mut h = [0u8; D0_HEALING_SLOT_LEN];
            h[D0_HEALING_SLOT_LEN / 2] = 0x01;
            h
        }),
        ("all ones", || [0xFF; D0_HEALING_SLOT_LEN]),
        ("alternating 0xAA", || [0xAA; D0_HEALING_SLOT_LEN]),
        ("single bit at byte 7", || {
            let mut h = [0u8; D0_HEALING_SLOT_LEN];
            h[7] = 0x01;
            h
        }),
    ];

    for (label, make) in patterns {
        let h = make();
        assert_eq!(
            check_deterministic_healing(&h),
            Err(D0Error::HealingNonzeroInDeterministicMode),
            "pattern '{label}' must be rejected by check_deterministic_healing"
        );
    }
}

// ── Ratchet determinism across 3+ epochs ─────────────────────────────────────

/// `ratchet_deterministic` is fully deterministic: calling it twice with the same
/// (state, epoch) inputs produces identical outputs. This is verified across a 3-epoch
/// chain (the same depth as D0-TV-004 in the inline KAT suite).
///
/// Note: SecretState intentionally omits PartialEq (no constant-time compare). We use
/// `coeffs_for_review()` to compare, which is the review/test accessor for this purpose.
#[test]
fn ratchet_is_reproducible_across_three_epochs() {
    // Build a valid initial state from a fixed, known coefficient array.
    // All coefficients set to 1 are valid (1 < q = 8_380_417).
    let init_coeffs = [1u32; D0_P_N];
    let p0 = SecretState::from_coeffs(init_coeffs).expect("valid state");

    // First chain: p0 -> p1 -> p2 -> p3
    let p1a = ratchet_deterministic(&p0, 0);
    let p2a = ratchet_deterministic(&p1a, 1);
    let p3a = ratchet_deterministic(&p2a, 2);

    // Second chain: identical inputs, must produce identical outputs
    let p1b = ratchet_deterministic(&p0, 0);
    let p2b = ratchet_deterministic(&p1b, 1);
    let p3b = ratchet_deterministic(&p2b, 2);

    assert_eq!(
        p1a.coeffs_for_review(),
        p1b.coeffs_for_review(),
        "ratchet epoch 0->1 must be reproducible"
    );
    assert_eq!(
        p2a.coeffs_for_review(),
        p2b.coeffs_for_review(),
        "ratchet epoch 1->2 must be reproducible"
    );
    assert_eq!(
        p3a.coeffs_for_review(),
        p3b.coeffs_for_review(),
        "ratchet epoch 2->3 must be reproducible"
    );
}

/// The ratchet is epoch-sensitive: advancing from epoch 0 and epoch 1 with the same
/// base state produces distinct outputs. This characterizes the preimage field order
/// — epoch_le is bound into the SHAKE256 input and changes the output.
#[test]
fn ratchet_output_depends_on_epoch() {
    let p0 = SecretState::from_coeffs([2u32; D0_P_N]).expect("valid state");

    let p_from_epoch0 = ratchet_deterministic(&p0, 0);
    let p_from_epoch1 = ratchet_deterministic(&p0, 1);

    assert_ne!(
        p_from_epoch0.coeffs_for_review(),
        p_from_epoch1.coeffs_for_review(),
        "ratchet with epoch=0 vs epoch=1 must produce different outputs (epoch is bound)"
    );
}

// ── Connected-healing gate ────────────────────────────────────────────────────

/// Placeholder: the connected-healing path is gated behind `d0-connected-healing` and
/// is currently a compile_error if the feature is enabled. This test documents the
/// intended post-review behavior and is kept ignored until the healing source is specified
/// and the feature is activated through a deliberate review decision.
///
/// activates post-review with connected-healing spec
#[test]
#[ignore = "activates post-review with connected-healing spec (feature gate is compile_error today)"]
fn connected_healing_advances_state_with_nonzero_nonce() {
    // This test intentionally does nothing. When `d0-connected-healing` is specified
    // and activated, replace this body with: a test that calls ratchet_internal with a
    // registry-issued nonce and asserts the output differs from ratchet_deterministic.
    //
    // Do NOT enable `d0-connected-healing` and do NOT call ratchet_internal with
    // non-zero healing until the post-review activation decision is made.
}
