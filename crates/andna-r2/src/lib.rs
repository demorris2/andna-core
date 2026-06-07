//! AN-DNA R2 — local policy authorization MVP.
//!
//! Scope:
//! - consumes Stage 1 output from R1 as `Stage1Outcome`;
//! - authorizes verified facts against a local registry snapshot;
//! - emits AUTHORIZED / NOT_AUTHORIZED / NOT_EVALUATED;
//! - computes a snapshot-bound `policy_digest`.
//!
//! Non-scope:
//! - no liboqs;
//! - no ML-DSA verification;
//! - no D0 derivation;
//! - no hardware attestation;
//! - no witness / transparency registry;
//! - no production R2 claims.
//!
//! R2 is deliberately pure and testable. The orchestration layer should run R1
//! first, extract `VerifiedFacts` only after CRYPTO_ACCEPT, then call R2.

pub mod facts;
pub mod policy;
pub mod registry;

pub use facts::{Stage1Outcome, VerifiedFacts};
pub use policy::{authorize, Reason, Stage2Decision, Stage2Status};
pub use registry::{Registry, RegistryEntry, RegistryError, SnapshotId};

/// Canonical length-prefix helper used by R2 digest preimages.
///
/// Encoding:
///     u32le(length) || bytes
///
/// This is not a public wire format. It is the local deterministic encoding
/// for snapshot and policy digest preimages.
pub(crate) fn lp(out: &mut Vec<u8>, bytes: &[u8]) {
    let len: u32 = bytes
        .len()
        .try_into()
        .expect("R2 canonical field too large");
    out.extend_from_slice(&len.to_le_bytes());
    out.extend_from_slice(bytes);
}
