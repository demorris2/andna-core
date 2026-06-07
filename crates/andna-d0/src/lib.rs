//! # andna-d0 — AN-DNA prover-side D0 derivation layer
//!
//! Spec: D0 Serialization Specification v0.3.0 (`D0_SPEC_VERSION = 0x02`).
//!
//! D0 derives the 32-byte ML-DSA-44 key-generation seed `xi_E` from secret epoch
//! state and evolves that state with a SHAKE256 hash-chain ratchet. `xi_E` is the
//! derivation boundary; ML-DSA-44 `KeyGen_internal(xi_E)` lives in [`mldsa`].
//!
//! ## INTEGRATION STATUS
//! **D0 → R1 bridge: cross-backend ACCEPT-path interop is evidence-backed.** The live
//! KAT `crates/core/tests/d0_fips204_to_liboqs_r1_interop_accepts.rs` runs
//! fips204 keygen+sign → liboqs/oqs-sys `verify_frame_v2` → ACCEPT for the fixed D0
//! test vector, plus tamper-rejection cases (bad signature → `SignatureInvalid`, bad
//! T_E → `PkHashMismatch`), and is gated in CI (the `interop` job). The claim is
//! BOUNDED to that vector and the ACCEPT + tamper paths — it is not a claim of full
//! protocol integration (R2 / policy authorization / multi-epoch are out of scope).
//!
//! ## Cryptographic backend policy (no stubs)
//! AN-DNA does not use stub, mock, toy, simulated, or placeholder cryptographic
//! backends in production or review builds. All cryptographic operations use named,
//! pinned, real implementations of standardized algorithms, with validation status
//! documented and known-answer tests enforced in CI. Test-only helpers are
//! `cfg(test)`- or feature-gated and must never substitute a fake backend.
//!
//! ## ML-DSA-44 backend — validation status
//!   * Official algorithm : FIPS 204 ML-DSA.
//!   * Implementation     : `fips204` crate, pinned `=0.4.6` (implementation
//!                          candidate — NOT official NIST software).
//!   * Validation status  : NOT claimed as FIPS 140-3 / CAVP validated.
//!   * Use                : D0 seeded keygen bridge only ([`mldsa`]).
//!   * R1 evidence path   : unchanged liboqs/oqs-sys verifier, in its own crate,
//!                          with no dependency on `andna-d0`.
//!
//! ## Secret-key lifecycle (software vs hardware profile)
//! `fips204`'s `PrivateKey` drop-zeroization is not independently confirmed here, so
//! the key-holding [`mldsa::EpochKeypair`] is SOFTWARE-PROFILE ONLY. Procurement-grade
//! host paths prefer [`mldsa::derive_epoch_public`] (retains/exposes no `sk`; the
//! backend generates it internally and drops it in scope) and
//! [`mldsa::sign_in_epoch`] (drops `sk` within the call). See the `mldsa` module note.
//!
//! ## SECURITY INVARIANT R-1 (full-state dependence)
//! The ratchet input MUST include the complete canonical `D0_STATE_RECORD_V1` (all
//! 256 coefficients). Per-coefficient derivation is forbidden — it would reduce
//! predecessor recovery to 256 independent ~2^23 searches and break forward secrecy.
//!
//! ## device_id16 / attestation
//! `device_id16` is bound (publicly) into the seed-derivation transcript — that gives
//! cross-device / cross-epoch domain separation only, NOT confidentiality and NOT, by
//! itself, hardware authenticity. `device_id16` MUST be bound to the attested hardware
//! identity (EK/AK) by R2 enrollment; D0 does not establish that binding. A
//! registry-assigned label not tied to attested hardware leaves Architecture Attack E open.

// The reserved healed mode must never compile to a silent placeholder: enabling the
// feature is a hard build failure until the mode is specified and analyzed.
#[cfg(feature = "d0-connected-healing")]
compile_error!(
    "feature `d0-connected-healing` is RESERVED and not yet specified. Enabling it \
     must fail the build until the connectivity-healed / counter-bound ratchet mode \
     is defined and security-analyzed. No placeholder implementation is permitted."
);

mod derive;
mod mldsa;

// ---- public API (explicit surface; no glob re-export) ----
// NOTE: `derive_xi` is intentionally NOT re-exported — `xi_E` is a signing-key seed.
// It is available only under `feature = "d0-test-vectors"` via `test_vectors`.
pub use derive::{
    check_deterministic_healing, ratchet_deterministic, validate_epoch_record,
    validate_state_record, D0Context, D0Error, SecretState,
};

// ---- public constants ----
pub use derive::{
    D0_EPOCH_RECORD_LEN, D0_HEALING_SLOT_LEN, D0_P_ENCODED_LEN, D0_P_N, D0_P_PROFILE_ID, D0_P_Q,
    D0_SPEC_VERSION, D0_STATE_RECORD_LEN, EPOCH_SEED_DOMAIN, MLDSA_SEED_DOMAIN,
    RATCHET_STATE_DOMAIN,
};

// ---- D0 -> ML-DSA bridge ----
// Preferred procurement paths: `derive_epoch_public` (retains/exposes no sk) and
// `sign_in_epoch` (scoped sk). `derive_epoch_keypair` / `EpochKeypair` are software-profile only.
pub use mldsa::{
    build_t_e, derive_epoch_keypair, derive_epoch_public, sign_in_epoch, t_e_hash64, EpochKeypair,
    EpochPublic,
};

// ---- review/KAT-only exposure (opt-in; exposes real derivations, never a fake) ----
#[cfg(feature = "d0-test-vectors")]
pub use derive::test_vectors;