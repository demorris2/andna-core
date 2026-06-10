//! # andna-seal — file sealing and verification over the AN-DNA frame
//!
//! Turns the D0 → R1 → R2 chain into a practical statement about a file:
//! *this file was sealed, it has not changed, the sealing identity is cryptographically
//! valid, and that identity is authorized by the supplied registry — here is the evidence.*
//!
//! ## How the binding works (no change to R1)
//! `mu_pre.ctx_hash` is signed over as part of `mu = SHAKE256(mu_pre)`, but the R1 verifier
//! never *interprets* it. So sealing binds a file by computing a canonical manifest of the
//! file, hashing it, and placing that hash in `ctx_hash`. The ML-DSA signature then covers
//! the binding (tampering it breaks the signature → R1 rejects), while R1 stays frozen and
//! this crate owns the file-binding semantics.
//!
//! ## Four independent, falsifiable checks (verify)
//! 1. R1 `verify_frame_v2` → **AUTHENTIC** (signature + identity bindings). *(unchanged R1.)*
//! 2. `manifest_hash == mu_pre.ctx_hash` → manifest matches what was signed.
//! 3. `file_hash == manifest.file_hash` → file content matches the manifest.
//!    (2 ∧ 3, given 1) → **UNCHANGED**.
//! 4. R2 `authorize` → **AUTHORIZED** / NOT_AUTHORIZED / not evaluated. *(unchanged R2.)*
//!
//! Failure isolation: tampered frame → step 1; tampered manifest → step 2; tampered file →
//! step 3; unknown/revoked identity → step 4.
//!
//! ## Scope (strict)
//! * **Seal ≠ encrypt.** This binds integrity + authenticity only. The file is NOT made
//!   confidential; a sealed file is readable. Confidentiality (an ML-KEM envelope) is out of
//!   scope and a separate future capability.
//! * **Software-profile identity.** The default [`SoftwareProfileSigner`] is a NON-PRODUCTION
//!   identity (seeded ML-DSA-44). It proves *possession of the sealing key at signing time* —
//!   not hardware custody, clone-resistance, or post-compromise safety. If the sealing seed is
//!   compromised, an attacker can mint valid-looking seals until the registry revokes or
//!   freezes that identity.
//! * **R1 frozen.** The binding lives entirely here via `ctx_hash`; the verifier is unchanged.
//!
//! ## Durability rule (v0)
//! A stable software-profile seal stays verifiable only as long as the registry continues to
//! authorize the signer's epoch and T_E hash. Because R2 v0 requires
//! `facts.epoch == registry.current_epoch`, advancing `current_epoch` (or removing the
//! authorized T_E hash) makes prior seals report `NOT_AUTHORIZED` (`epoch_stale`) — they are
//! still cryptographically authentic and unchanged, but no longer *authorized* under the new
//! registry state, unless verified against an archival/as-of registry snapshot. The stable
//! epoch avoids ratchet-driven expiry; it does not make authorization permanent.
//!
//! The [`Signer`] trait is the architecture: a D0-ratchet backend can be added later, paired
//! with verify-as-of-snapshot semantics (its epoch evolves, so its seals would otherwise
//! expire under R2's epoch-freshness rule).

#![forbid(unsafe_code)]

mod evidence;
mod manifest;
mod seal;
mod signer;
mod verify;

pub use evidence::{
    DeterministicEvidence, RuntimeContext, SealEvidenceV1, EVIDENCE_SCHEMA_VERSION,
};
pub use manifest::{
    Manifest, SealError, DIGEST_ALGORITHM, MANIFEST_POLICY_V0, MANIFEST_SCHEMA_VERSION,
};
pub use seal::{seal_file, SealedBundle, FRAME_ENCODING, SIDECAR_SCHEMA_VERSION};
pub use signer::{Signer, SoftwareProfileSigner, PK_E_LEN};
pub use verify::{verify_sealed, SealVerifyResult, Verdict};

// Registry + combined-decision types callers need, surfaced via the pipeline (which
// re-exports them from andna-r2) so callers don't depend on andna-r2 directly.
pub use andna_pipeline::{CombinedDecision, Registry, RegistryEntry};

/// Canonical length-prefixed append: `u32` little-endian length, then bytes. Shared by the
/// manifest canonical encoding so variable-length fields can't be ambiguously concatenated.
pub(crate) fn lp(buf: &mut Vec<u8>, bytes: &[u8]) {
    buf.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
    buf.extend_from_slice(bytes);
}
