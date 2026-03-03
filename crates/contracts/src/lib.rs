//! # AN-DNA vNext Phase 1 — Canonical Contracts
//!
//! Single source of truth for all constants, offsets, and size invariants.
//! Every language binding MUST derive from this crate or its generated artifacts.
//!
//! **Change control**: Any modification requires new spec version + KAT refresh.

#![no_std]
#![forbid(unsafe_code)]

// ── ML-DSA-44 Ring Constants (FIPS 204, Category 2) ────────────────────────

pub const MLDSA44_Q: u32 = 8_380_417;
pub const MLDSA44_N: usize = 256;
pub const MLDSA44_K: usize = 4;
pub const MLDSA44_ELL: usize = 4;
pub const MLDSA44_D: usize = 13;
pub const MLDSA44_ETA: usize = 2;
pub const MLDSA44_TAU: usize = 39;
pub const MLDSA44_OMEGA: usize = 80;
pub const MLDSA44_GAMMA1: u32 = 1 << 17;
pub const MLDSA44_GAMMA2: u32 = (MLDSA44_Q - 1) / 88;
pub const MLDSA44_ALPHA: u32 = 2 * MLDSA44_GAMMA2;
pub const MLDSA44_BETA: u32 = (MLDSA44_TAU as u32) * (MLDSA44_ETA as u32);

// ── Domain Separation ──────────────────────────────────────────────────────

/// Domain separator field length in mu_pre (locked by offset chain to 9).
///
/// Phase-1 canonical: "ANDNAAUTH" = 9 ASCII bytes, no hyphen, no NUL.
/// The hyphenated form "ANDNA-AUTH" (10 bytes) is reserved for a future
/// MU_PRE_VERSION = 0x02 with shifted offsets and new KATs.
/// Hex: 41 4E 44 4E 41 41 55 54 48
pub const DOMAIN_SEP_LEN: usize = 9;
pub const DOMAIN_SEP: [u8; DOMAIN_SEP_LEN] = *b"ANDNAAUTH";

pub const EPOCH_SEED_DOMAIN: &[u8; 16] = b"ANDNA-EPOCH-SEED";
pub const MLDSA_SEED_DOMAIN: &[u8; 16] = b"ANDNA-MLDSA-SEED";

/// V1 alias (active). Use in code that needs version-aware branching.
pub const DOMAIN_SEP_V1: [u8; 9] = DOMAIN_SEP;

/// V2 (future, NOT enabled): "ANDNA-AUTH" = 10 bytes, requires
/// MU_PRE_VERSION 0x02 + shifted offsets + KAT regen.
pub const DOMAIN_SEP_V2_LEN: usize = 10;
// pub const DOMAIN_SEP_V2: [u8; 10] = *b"ANDNA-AUTH"; // uncomment under v2 spec

// ── mu_pre Layout (274 bytes) ──────────────────────────────────────────────

pub const MU_PRE_LEN: usize = 274;

pub const MU_PRE_PK_HASH_OFF: usize = 0;
pub const MU_PRE_PK_HASH_LEN: usize = 64;

pub const MU_PRE_DOMAIN_SEP_OFF: usize = 64;
pub const MU_PRE_DOMAIN_SEP_LEN: usize = DOMAIN_SEP_LEN;

pub const MU_PRE_VERSION_OFF: usize = 73;
pub const MU_PRE_VERSION_LEN: usize = 1;
pub const MU_PRE_VERSION_VAL: u8 = 0x01;

pub const MU_PRE_DEVICE_ID32_OFF: usize = 74;
pub const MU_PRE_DEVICE_ID32_LEN: usize = 32;

pub const MU_PRE_EPOCH_OFF: usize = 106;
pub const MU_PRE_EPOCH_LEN: usize = 8;

pub const MU_PRE_SID_OFF: usize = 114;
pub const MU_PRE_SID_LEN: usize = 32;

pub const MU_PRE_ND_OFF: usize = 146;
pub const MU_PRE_ND_LEN: usize = 32;

pub const MU_PRE_NS_OFF: usize = 178;
pub const MU_PRE_NS_LEN: usize = 32;

pub const MU_PRE_CTX_HASH_OFF: usize = 210;
pub const MU_PRE_CTX_HASH_LEN: usize = 32;

pub const MU_PRE_POLICY_HASH_OFF: usize = 242;
pub const MU_PRE_POLICY_HASH_LEN: usize = 32;

// ── T_E Layout (Epoch Public Key) ──────────────────────────────────────────

pub const TE_RHO_OFF: usize = 0;
pub const TE_RHO_LEN: usize = 32;

pub const TE_T1_OFF: usize = 32;
pub const TE_T1_LEN: usize = 1280;

pub const TE_EPOCH_OFF: usize = 1312;
pub const TE_EPOCH_LEN: usize = 8;

/// device_id16: 16-byte compact TE metadata (Phase 1).
/// Distinct from mu_pre device_id32 (32-byte identity anchor).
pub const TE_DEVICE_ID16_OFF: usize = 1320;
pub const TE_DEVICE_ID16_LEN: usize = 16;

pub const TE_V1_LEN: usize = 1336;  // Phase 1, ACTIVE
pub const TE_V2_LEN: usize = 1352;  // Phase 2+, defined NOT enabled
pub const TE_LEN: usize = TE_V1_LEN;

// ── Signature (2420 bytes) ─────────────────────────────────────────────────

pub const SIG_Z_OFF: usize = 0;
pub const SIG_Z_LEN: usize = 2304;
pub const SIG_H_OFF: usize = 2304;
pub const SIG_H_LEN: usize = 84;
pub const SIG_C_TILDE_OFF: usize = 2388;
pub const SIG_C_TILDE_LEN: usize = 32;
pub const SIG_LEN: usize = 2420;

// ── Frame v2 ───────────────────────────────────────────────────────────────

pub const FRAME_V2_MU_PRE_OFF: usize = 0;
pub const FRAME_V2_TE_OFF: usize = MU_PRE_LEN;
pub const FRAME_V2_SIG_OFF: usize = MU_PRE_LEN + TE_LEN;
pub const FRAME_V2_LEN: usize = MU_PRE_LEN + TE_LEN + SIG_LEN;

// ── SHAKE256 Output Lengths ────────────────────────────────────────────────

pub const PK_HASH_LEN: usize = 64;
pub const MU_LEN: usize = 64;
pub const C_TILDE_OUTPUT_LEN: usize = 32;

// ── Caching ────────────────────────────────────────────────────────────────

pub const TE_CACHE_POS_TTL_S: u64 = 600;
pub const TE_CACHE_NEG_TTL_S: u64 = 45;

// ── Compile-Time Assertions ────────────────────────────────────────────────

const _: () = assert!(MU_PRE_PK_HASH_LEN + MU_PRE_DOMAIN_SEP_LEN + MU_PRE_VERSION_LEN
    + MU_PRE_DEVICE_ID32_LEN + MU_PRE_EPOCH_LEN + MU_PRE_SID_LEN
    + MU_PRE_ND_LEN + MU_PRE_NS_LEN + MU_PRE_CTX_HASH_LEN
    + MU_PRE_POLICY_HASH_LEN == MU_PRE_LEN);
const _: () = assert!(TE_RHO_LEN + TE_T1_LEN + TE_EPOCH_LEN + TE_DEVICE_ID16_LEN == TE_V1_LEN);
const _: () = assert!(TE_V1_LEN == 1336);
const _: () = assert!(TE_V2_LEN == 1352);
const _: () = assert!(SIG_Z_LEN + SIG_H_LEN + SIG_C_TILDE_LEN == SIG_LEN);
const _: () = assert!(SIG_LEN == 2420);
const _: () = assert!(FRAME_V2_LEN == 4030);
// Offset chain contiguity
const _: () = assert!(MU_PRE_DOMAIN_SEP_OFF == MU_PRE_PK_HASH_LEN);
const _: () = assert!(MU_PRE_VERSION_OFF == MU_PRE_DOMAIN_SEP_OFF + MU_PRE_DOMAIN_SEP_LEN);
const _: () = assert!(MU_PRE_DEVICE_ID32_OFF == MU_PRE_VERSION_OFF + MU_PRE_VERSION_LEN);
const _: () = assert!(MU_PRE_EPOCH_OFF == MU_PRE_DEVICE_ID32_OFF + MU_PRE_DEVICE_ID32_LEN);
const _: () = assert!(MU_PRE_SID_OFF == MU_PRE_EPOCH_OFF + MU_PRE_EPOCH_LEN);
const _: () = assert!(MU_PRE_ND_OFF == MU_PRE_SID_OFF + MU_PRE_SID_LEN);
const _: () = assert!(MU_PRE_NS_OFF == MU_PRE_ND_OFF + MU_PRE_ND_LEN);
const _: () = assert!(MU_PRE_CTX_HASH_OFF == MU_PRE_NS_OFF + MU_PRE_NS_LEN);
const _: () = assert!(MU_PRE_POLICY_HASH_OFF == MU_PRE_CTX_HASH_OFF + MU_PRE_CTX_HASH_LEN);
const _: () = assert!(MU_PRE_POLICY_HASH_OFF + MU_PRE_POLICY_HASH_LEN == MU_PRE_LEN);
const _: () = assert!(MLDSA44_BETA == 78);
const _: () = assert!(MLDSA44_GAMMA1 == 131072);
const _: () = assert!(MLDSA44_GAMMA2 == 95232);

#[cfg(test)]
mod tests {
    use super::*;
    #[test] fn mu_pre_total() { assert_eq!(MU_PRE_LEN, 274); }
    #[test] fn te_lengths() { assert_eq!(TE_V1_LEN, 1336); assert_eq!(TE_LEN, TE_V1_LEN); }
    #[test] fn frame_v2() { assert_eq!(FRAME_V2_LEN, 4030); }
    #[test] fn hex_offsets() {
        assert_eq!(MU_PRE_PK_HASH_OFF, 0x0000);
        assert_eq!(MU_PRE_DOMAIN_SEP_OFF, 0x0040);
        assert_eq!(MU_PRE_VERSION_OFF, 0x0049);
        assert_eq!(MU_PRE_DEVICE_ID32_OFF, 0x004A);
        assert_eq!(MU_PRE_EPOCH_OFF, 0x006A);
        assert_eq!(MU_PRE_SID_OFF, 0x0072);
        assert_eq!(MU_PRE_ND_OFF, 0x0092);
        assert_eq!(MU_PRE_NS_OFF, 0x00B2);
        assert_eq!(MU_PRE_CTX_HASH_OFF, 0x00D2);
        assert_eq!(MU_PRE_POLICY_HASH_OFF, 0x00F2);
    }
}
