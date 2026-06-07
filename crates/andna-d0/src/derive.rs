//! D0 derivation core (spec v0.3.0): canonical records, `Seed_E` / `xi_E`, the
//! SHAKE256 hash-chain ratchet, and record validation. ML-DSA-independent — `xi_E`
//! is the boundary.
//!
//! SECURITY INVARIANT R-1 (full-state dependence): the ratchet sampler input MUST
//! include the complete canonical `D0_STATE_RECORD_V1` (all 256 coefficients). Never
//! derive a coefficient from a per-coefficient input — that would reduce predecessor
//! recovery to 256 independent ~2^23 searches and collapse forward secrecy.
//!
//! Domain-label / version note: the three domain labels carry `-v1` as STABLE
//! role-namespace tags (they name the hash's role), NOT the D0 spec version.
//! Separation between D0 spec versions is provided by `D0_SPEC_VERSION` inside every
//! hashed record: with version `0x02` the test state-record hash is `19da777f…`;
//! with the retired `0x01` it is `25efd74c…` — a different value, so v0.2 and v0.3
//! outputs cannot collide even though they share the namespace labels.
//!
//! Secret-output exposure: `xi_E` is a signing-key seed. `derive_xi` is `pub(crate)`
//! and returns an auto-wiping `Zeroizing<[u8; 32]>`; it is NOT in the default public
//! API (exposed only under `feature = "d0-test-vectors"`).

use sha3::digest::{ExtendableOutput, Update, XofReader};
use sha3::Shake256;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

// ---------- D0 derivation constants (local to andna-d0 until v0.3 review closes) ----------
// DEVICE_ID16_LEN is a D0 derivation input length (bound into the epoch record), so it
// lives here rather than being imported. It is pinned to the shared T_E device-id field
// width at compile time so the two can never silently diverge.
pub const DEVICE_ID16_LEN: usize = 16;
const _: () = assert!(DEVICE_ID16_LEN == andna_contracts::TE_DEVICE_ID16_LEN);

pub const D0_SPEC_VERSION: u8 = 0x02; // hash-chain ratchet (0x01 was the retired byte-additive ratchet)
pub const D0_P_PROFILE_ID: u8 = 0x02; // P256Q8380417_LE32
pub const D0_RECORD_RESERVED_LEN: usize = 6;
pub const D0_HEALING_SLOT_LEN: usize = 32;

pub const D0_P_N: usize = 256;
pub const D0_P_Q: u32 = 8_380_417;
pub const D0_P_COEFF_WIDTH: usize = 4;
pub const D0_P_ENCODED_LEN: usize = D0_P_N * D0_P_COEFF_WIDTH; // 1024
pub const D0_STATE_RECORD_LEN: usize = 1 + 1 + D0_RECORD_RESERVED_LEN + D0_P_ENCODED_LEN; // 1032
pub const D0_EPOCH_RECORD_LEN: usize =
    1 + 1 + D0_RECORD_RESERVED_LEN + 8 + DEVICE_ID16_LEN + D0_P_ENCODED_LEN; // 1056

pub const EPOCH_SEED_DOMAIN: &[u8] = b"ANDNA-D0-EPOCH-SEED-v1";
pub const MLDSA_SEED_DOMAIN: &[u8] = b"ANDNA-D0-MLDSA-SEED-v1";
pub const RATCHET_STATE_DOMAIN: &[u8] = b"ANDNA-D0-RATCHET-STATE-v1";

/// Rejection bound `floor(2^32 / q) * q`. Discard a 4-byte draw `v >= bound`, else
/// accept `v % q`. Mod-bias-free. Value (< 2^32) fits in u32.
const REJECT_BOUND: u32 = ((0x1_0000_0000u64 / D0_P_Q as u64) * D0_P_Q as u64) as u32;

// ---------- error taxonomy (spec §15; pub enum — unused variants are public API) ----------
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum D0Error {
    StateRecordLength,
    EpochRecordLength,
    Version,
    Profile,
    ReservedNonzero,
    DeviceIdLen,
    PolyLen,
    PolyCoeffRange,
    SeedDerivation,
    RatchetDerivation,
    MldsaKeygen,
    TeLength,
    HealingNonzeroInDeterministicMode,
}

// ---------- secret state ----------
/// `P_E`: 256 coefficients in `[0, q)`. Private field (no raw exposure); zeroized on
/// drop (spec §18); intentionally NOT `Clone` (avoids accidental duplicate live
/// copies of secret state).
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SecretState {
    coeffs: [u32; D0_P_N],
}

impl SecretState {
    /// Construct from coefficients, enforcing the canonical range `[0, q)`. On
    /// rejection the moved-in array is zeroized before returning (no secret residue).
    pub fn from_coeffs(mut coeffs: [u32; D0_P_N]) -> Result<Self, D0Error> {
        for &c in coeffs.iter() {
            if c >= D0_P_Q {
                coeffs.zeroize();
                return Err(D0Error::PolyCoeffRange);
            }
        }
        Ok(Self { coeffs })
    }

    /// Internal read access for derivation/serialization within this crate.
    pub(crate) fn coeffs(&self) -> &[u32; D0_P_N] {
        &self.coeffs
    }

    /// Read-only coefficient access for external KAT/review tooling ONLY.
    #[cfg(any(test, feature = "d0-test-vectors"))]
    pub fn coeffs_for_review(&self) -> &[u32; D0_P_N] {
        &self.coeffs
    }
}

// ---------- low-level helpers ----------
/// SHAKE256 over the concatenation of `parts`, into a zeroizing heap buffer (so the
/// output is wiped on drop regardless of caller discipline).
fn shake256_parts(parts: &[&[u8]], out_len: usize) -> Zeroizing<Vec<u8>> {
    let mut h = Shake256::default();
    for p in parts {
        h.update(p);
    }
    let mut reader = h.finalize_xof();
    let mut out = vec![0u8; out_len];
    reader.read(&mut out);
    Zeroizing::new(out)
}

/// Canonical little-endian coefficient encoding (single source of truth).
fn encode_p(p: &[u32; D0_P_N]) -> [u8; D0_P_ENCODED_LEN] {
    let mut out = [0u8; D0_P_ENCODED_LEN];
    for (i, &c) in p.iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&c.to_le_bytes());
    }
    out
}

fn state_record(p: &[u32; D0_P_N]) -> [u8; D0_STATE_RECORD_LEN] {
    let mut r = [0u8; D0_STATE_RECORD_LEN];
    r[0] = D0_SPEC_VERSION;
    r[1] = D0_P_PROFILE_ID;
    // r[2..8] reserved == 0
    let mut enc = encode_p(p);
    r[8..].copy_from_slice(&enc);
    enc.zeroize(); // wipe the transient secret copy
    r
}

fn epoch_record(
    p: &[u32; D0_P_N],
    epoch: u64,
    device_id16: &[u8; DEVICE_ID16_LEN],
) -> [u8; D0_EPOCH_RECORD_LEN] {
    let mut r = [0u8; D0_EPOCH_RECORD_LEN];
    r[0] = D0_SPEC_VERSION;
    r[1] = D0_P_PROFILE_ID;
    // r[2..8] reserved == 0
    r[8..16].copy_from_slice(&epoch.to_le_bytes());
    r[16..16 + DEVICE_ID16_LEN].copy_from_slice(device_id16);
    let mut enc = encode_p(p);
    r[16 + DEVICE_ID16_LEN..].copy_from_slice(&enc);
    enc.zeroize(); // wipe the transient secret copy
    r
}

/// SHAKE256 over `parts` -> 256 full-width coefficients via mod-bias-free rejection
/// sampling. The XOF is read incrementally (4 bytes at a time), so the sampler is
/// total — it never exhausts a fixed buffer. The byte stream is identical to
/// pre-squeezing a large buffer and chunking it.
///
/// SECURITY INVARIANT R-1: callers MUST pass the full canonical state record as a
/// part. Never sample from a per-coefficient input.
fn sample_coeffs_from_parts(parts: &[&[u8]]) -> [u32; D0_P_N] {
    let mut h = Shake256::default();
    for p in parts {
        h.update(p);
    }
    let mut reader = h.finalize_xof();
    let mut out = [0u32; D0_P_N];
    let mut buf = [0u8; 4];
    let mut count = 0usize;
    while count < D0_P_N {
        reader.read(&mut buf);
        let v = u32::from_le_bytes(buf);
        if v < REJECT_BOUND {
            out[count] = v % D0_P_Q;
            count += 1;
        }
    }
    buf.zeroize();
    out
}

// ---------- public derivation API ----------

/// Public derivation context: the epoch and device identity bound into `Seed_E`.
#[derive(Clone)]
pub struct D0Context {
    pub epoch: u64,
    pub device_id16: [u8; DEVICE_ID16_LEN],
}

/// `Seed_E = SHAKE256(EPOCH_SEED_DOMAIN || D0_EPOCH_RECORD_V1, 32)`. Secret
/// intermediate — internal only.
fn seed_e(state: &SecretState, epoch: u64, device_id16: &[u8; DEVICE_ID16_LEN]) -> [u8; 32] {
    let mut rec = epoch_record(state.coeffs(), epoch, device_id16);
    let out = shake256_parts(&[EPOCH_SEED_DOMAIN, &rec[..]], 32);
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&out[..]);
    rec.zeroize();
    seed
}

/// `xi_E = SHAKE256(MLDSA_SEED_DOMAIN || Seed_E, 32)`. Internal only.
fn xi_from_seed(seed: &[u8; 32]) -> [u8; 32] {
    let out = shake256_parts(&[MLDSA_SEED_DOMAIN, &seed[..]], 32);
    let mut xi = [0u8; 32];
    xi.copy_from_slice(&out[..]);
    xi
}

/// Full derivation `P_E -> xi_E`, zeroizing `Seed_E` internally and returning the
/// seed in an auto-wiping wrapper. INTERNAL (`pub(crate)`): `xi_E` is a signing-key
/// seed and is NOT part of the default public API — production callers use the
/// `mldsa` bridge (`derive_epoch_public` / `sign_in_epoch` / `derive_epoch_keypair`).
/// Exposed publicly only under `feature = "d0-test-vectors"` via [`test_vectors`].
pub(crate) fn derive_xi(state: &SecretState, ctx: &D0Context) -> Zeroizing<[u8; 32]> {
    let mut seed = seed_e(state, ctx.epoch, &ctx.device_id16);
    let xi = xi_from_seed(&seed);
    seed.zeroize();
    Zeroizing::new(xi)
}

/// Deterministic SHAKE256 hash-chain ratchet `P_E -> P_{E+1}` (healing = 0; the only
/// mode defined in v0.3). `P_{E+1}` is a fresh full-width pseudorandom draw, NOT a
/// perturbation of `P_E` (Invariant R-1).
pub fn ratchet_deterministic(state: &SecretState, epoch: u64) -> SecretState {
    ratchet_step(state, epoch, &[0u8; D0_HEALING_SLOT_LEN])
}

/// Internal ratchet over an explicit healing field. PRIVATE: v0.3 defines no
/// non-zero healing mode, so no public entry point accepts non-zero healing. The
/// healed mode (when specified) is exposed behind `feature = "d0-connected-healing"`
/// as a separately analyzed security mode.
fn ratchet_step(
    state: &SecretState,
    epoch: u64,
    healing: &[u8; D0_HEALING_SLOT_LEN],
) -> SecretState {
    let mut sr = state_record(state.coeffs());
    let epoch_le = epoch.to_le_bytes();
    let next = sample_coeffs_from_parts(&[
        RATCHET_STATE_DOMAIN,
        &epoch_le[..],
        &healing[..],
        &sr[..],
    ]);
    sr.zeroize();
    SecretState { coeffs: next }
}

/// Deterministic-mode guard for decoded records: the healing slot MUST be all-zero
/// in v0.3. Use when validating an externally supplied ratchet input.
pub fn check_deterministic_healing(healing: &[u8; D0_HEALING_SLOT_LEN]) -> Result<(), D0Error> {
    if healing.iter().any(|&b| b != 0) {
        return Err(D0Error::HealingNonzeroInDeterministicMode);
    }
    Ok(())
}

// ---------- record validation (spec §5.4 / §6.4; version pinned to 0x02) ----------

pub fn validate_state_record(bytes: &[u8]) -> Result<(), D0Error> {
    if bytes.len() != D0_STATE_RECORD_LEN {
        return Err(D0Error::StateRecordLength);
    }
    if bytes[0] != D0_SPEC_VERSION {
        return Err(D0Error::Version);
    }
    if bytes[1] != D0_P_PROFILE_ID {
        return Err(D0Error::Profile);
    }
    if bytes[2..8].iter().any(|&b| b != 0) {
        return Err(D0Error::ReservedNonzero);
    }
    validate_encoded_poly(&bytes[8..])
}

pub fn validate_epoch_record(bytes: &[u8]) -> Result<(), D0Error> {
    if bytes.len() != D0_EPOCH_RECORD_LEN {
        return Err(D0Error::EpochRecordLength);
    }
    if bytes[0] != D0_SPEC_VERSION {
        return Err(D0Error::Version);
    }
    if bytes[1] != D0_P_PROFILE_ID {
        return Err(D0Error::Profile);
    }
    if bytes[2..8].iter().any(|&b| b != 0) {
        return Err(D0Error::ReservedNonzero);
    }
    // bytes[8..16] = epoch, bytes[16..16+DEVICE_ID16_LEN] = device_id16 (no value checks here)
    validate_encoded_poly(&bytes[16 + DEVICE_ID16_LEN..])
}

fn validate_encoded_poly(poly: &[u8]) -> Result<(), D0Error> {
    if poly.len() != D0_P_ENCODED_LEN {
        return Err(D0Error::PolyLen);
    }
    for chunk in poly.chunks_exact(4) {
        let c = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
        if c >= D0_P_Q {
            return Err(D0Error::PolyCoeffRange);
        }
    }
    Ok(())
}

// ---------- review/KAT-only exposure (opt-in; exposes real derivations) ----------
/// Test/review-only access to intermediate secret derivations and secret-record
/// serialization, for regenerating and cross-checking KATs. NOT part of the default
/// public API and never a substitute backend. A production build must not enable
/// `d0-test-vectors` unless the release profile approves it.
#[cfg(feature = "d0-test-vectors")]
pub mod test_vectors {
    use super::*;

    /// `xi_E` (signing-key seed) in an auto-wiping wrapper — review/KAT only.
    pub fn derive_xi(state: &SecretState, ctx: &D0Context) -> Zeroizing<[u8; 32]> {
        super::derive_xi(state, ctx)
    }
    pub fn seed_e(state: &SecretState, epoch: u64, device_id16: &[u8; DEVICE_ID16_LEN]) -> [u8; 32] {
        super::seed_e(state, epoch, device_id16)
    }
    pub fn xi_from_seed(seed: &[u8; 32]) -> [u8; 32] {
        super::xi_from_seed(seed)
    }
    pub fn encode_p_for_review(state: &SecretState) -> [u8; D0_P_ENCODED_LEN] {
        super::encode_p(state.coeffs())
    }
    /// SECRET: contains `P_E`. KAT generation / review only.
    pub fn serialize_secret_state_record_for_review(
        state: &SecretState,
    ) -> [u8; D0_STATE_RECORD_LEN] {
        super::state_record(state.coeffs())
    }
    /// SECRET: contains `P_E`. KAT generation / review only.
    pub fn serialize_secret_epoch_record_for_review(
        state: &SecretState,
        epoch: u64,
        device_id16: &[u8; DEVICE_ID16_LEN],
    ) -> [u8; D0_EPOCH_RECORD_LEN] {
        super::epoch_record(state.coeffs(), epoch, device_id16)
    }

    /// Published D0 test fixture `P_0` = rejection-sample over
    /// `SHAKE256("ANDNA-D0-TEST-P0-v1")`. Zero real entropy — review/KAT use only.
    /// Matches `d0_reference_vectors_v2.py` and the in-crate KATs.
    pub fn p0_test_fixture() -> SecretState {
        SecretState {
            coeffs: super::sample_coeffs_from_parts(&[b"ANDNA-D0-TEST-P0-v1".as_slice()]),
        }
    }

    /// Published test `device_id16` = `SHAKE256("ANDNA-D0-TEST-DEVICE-v1", 16)`
    /// (= `3762eea8…2cc7`). Review/KAT use only.
    pub fn test_device_id16() -> [u8; DEVICE_ID16_LEN] {
        let mut d = [0u8; DEVICE_ID16_LEN];
        d.copy_from_slice(
            &super::shake256_parts(&[b"ANDNA-D0-TEST-DEVICE-v1".as_slice()], DEVICE_ID16_LEN)[..],
        );
        d
    }
}

// ===================================================================
// KATs — assert the spec v0.3.0 §14 reference vectors (parity oracle).
// Must match d0_reference_vectors_v2.py bit-for-bit.
// ===================================================================
#[cfg(test)]
mod kat {
    use super::*;
    use sha3::{Digest, Sha3_256};

    const TEST_DEVICE_DOMAIN: &[u8] = b"ANDNA-D0-TEST-DEVICE-v1";
    const TEST_P0_DOMAIN: &[u8] = b"ANDNA-D0-TEST-P0-v1";

    fn to_hex(b: &[u8]) -> String {
        let mut s = String::with_capacity(b.len() * 2);
        for x in b {
            s.push_str(&format!("{:02x}", x));
        }
        s
    }
    fn sha3(b: &[u8]) -> String {
        to_hex(Sha3_256::digest(b).as_ref())
    }
    fn dev() -> [u8; DEVICE_ID16_LEN] {
        let mut d = [0u8; DEVICE_ID16_LEN];
        d.copy_from_slice(&shake256_parts(&[TEST_DEVICE_DOMAIN], DEVICE_ID16_LEN)[..]);
        d
    }
    fn p0() -> SecretState {
        SecretState {
            coeffs: sample_coeffs_from_parts(&[TEST_P0_DOMAIN]),
        }
    }

    #[test]
    fn vectors_match_spec_v0_3() {
        let d = dev();
        assert_eq!(to_hex(&d), "3762eea87331d26335d048c669ae2cc7");

        let p0 = p0();
        assert_eq!(
            &p0.coeffs()[0..8],
            &[4973729u32, 1827450, 6853638, 6332654, 936934, 5946350, 8331213, 541605]
        );

        // ---- D0-TV-000: epoch-0 records + seed ----
        assert_eq!(
            sha3(&encode_p(p0.coeffs())),
            "05ed64ba4e5f8682b82cf4d3a801333ee7db47fed030712d99d118056aad8039"
        );
        assert_eq!(
            sha3(&state_record(p0.coeffs())),
            "19da777fcacf584e41f46b24cc4f0c2784f8f9c840d644476e3a74829e1774db"
        );
        assert_eq!(
            sha3(&epoch_record(p0.coeffs(), 0, &d)),
            "2c2fb0d44f7dc5b3b3fca183caa2462bf303a69e8571dfd5ee96d631b0d1bab0"
        );

        let seed0 = seed_e(&p0, 0, &d);
        assert_eq!(
            to_hex(&seed0),
            "ec4274cf909f43fa2aaf12737a258232887732c72d8f616debc90db9dc3a007f"
        );
        let ctx0 = D0Context { epoch: 0, device_id16: d };
        assert_eq!(
            to_hex(&derive_xi(&p0, &ctx0)[..]),
            "7c39378612176befb1d556c5f26ace6fc025901ccc651edfcc99c85308e58f54"
        );

        // ---- D0-TV-001: hash-chain ratchet epoch 0 -> 1 ----
        let p1 = ratchet_deterministic(&p0, 0);
        assert_eq!(
            &p1.coeffs()[0..8],
            &[5031199u32, 1353440, 2416873, 4667673, 6497221, 4598722, 4122511, 1707665]
        );
        assert_eq!(
            sha3(&encode_p(p1.coeffs())),
            "6709075154bc5e2f6843df01fbac38b7dd0abd9e2c10f4bc659a666b9ec84e48"
        );

        // ---- D0-TV-002: epoch-1 seed ----
        let ctx1 = D0Context { epoch: 1, device_id16: d };
        assert_eq!(
            to_hex(&derive_xi(&p1, &ctx1)[..]),
            "565b4b95f4a15a97a77d2b1c02bc0d4e60b83386425d4234c3efc0fa64140a88"
        );

        // ---- D0-TV-003 / 004: ratchet 1 -> 2 and epoch-2 seed ----
        let p2 = ratchet_deterministic(&p1, 1);
        assert_eq!(
            &p2.coeffs()[0..8],
            &[8004808u32, 8242042, 1693018, 246830, 3116329, 1293217, 3189366, 1737664]
        );
        let ctx2 = D0Context { epoch: 2, device_id16: d };
        assert_eq!(
            to_hex(&derive_xi(&p2, &ctx2)[..]),
            "980650fffe637472372a89950d59ffefc2e7f7544094a84be58f7403c371d1c6"
        );
    }

    /// Regression for the retired v0.2 weakness: consecutive states must NOT share
    /// high-order bits. Random expectation ~1/256; the additive walk was ~248/256.
    #[test]
    fn ratchet_decorrelates_high_bits() {
        let p0 = p0();
        let p1 = ratchet_deterministic(&p0, 0);
        let shared = (0..D0_P_N)
            .filter(|&i| (p0.coeffs()[i] >> 15) == (p1.coeffs()[i] >> 15))
            .count();
        assert!(shared < 10, "top-8-bit agreement too high: {}/256", shared);
    }

    /// from_coeffs must reject out-of-range coefficients.
    #[test]
    fn from_coeffs_enforces_range() {
        let mut c = [0u32; D0_P_N];
        c[0] = D0_P_Q; // == q, illegal
        // SecretState intentionally implements neither Debug nor PartialEq (it holds
        // secret coefficients; a Debug impl could leak P_E into logs/panics, and
        // PartialEq invites non-constant-time comparison). So match the error variant
        // rather than asserting equality on the whole Result.
        assert!(matches!(
            SecretState::from_coeffs(c),
            Err(D0Error::PolyCoeffRange)
        ));
        c[0] = D0_P_Q - 1; // legal
        assert!(SecretState::from_coeffs(c).is_ok());
    }

    /// Record length / field-validation coverage (lengths, reserved, profile, version).
    #[test]
    fn record_length_and_field_validation() {
        let p0 = p0();
        let d = dev();

        // exact good records validate
        assert_eq!(validate_state_record(&state_record(p0.coeffs())), Ok(()));
        assert_eq!(validate_epoch_record(&epoch_record(p0.coeffs(), 0, &d)), Ok(()));

        // record-length constants are exactly as specified
        assert_eq!(D0_STATE_RECORD_LEN, 1032);
        assert_eq!(D0_EPOCH_RECORD_LEN, 1056);

        // length: short and long state records rejected
        let st = state_record(p0.coeffs());
        assert_eq!(
            validate_state_record(&st[..st.len() - 1]),
            Err(D0Error::StateRecordLength)
        );
        let mut too_long = st.to_vec();
        too_long.push(0);
        assert_eq!(validate_state_record(&too_long), Err(D0Error::StateRecordLength));

        // short epoch record rejected
        let ep = epoch_record(p0.coeffs(), 0, &d);
        assert_eq!(
            validate_epoch_record(&ep[..ep.len() - 1]),
            Err(D0Error::EpochRecordLength)
        );

        // reserved nonzero (state + epoch)
        let mut r = state_record(p0.coeffs());
        r[2] = 1;
        assert_eq!(validate_state_record(&r), Err(D0Error::ReservedNonzero));
        let mut e = epoch_record(p0.coeffs(), 0, &d);
        e[3] = 1;
        assert_eq!(validate_epoch_record(&e), Err(D0Error::ReservedNonzero));

        // wrong profile (state + epoch)
        let mut r = state_record(p0.coeffs());
        r[1] = 0x01;
        assert_eq!(validate_state_record(&r), Err(D0Error::Profile));
        let mut e = epoch_record(p0.coeffs(), 0, &d);
        e[1] = 0x00;
        assert_eq!(validate_epoch_record(&e), Err(D0Error::Profile));

        // out-of-range coefficient rejected
        let mut bad = state_record(p0.coeffs());
        bad[8..12].copy_from_slice(&D0_P_Q.to_le_bytes());
        assert_eq!(validate_state_record(&bad), Err(D0Error::PolyCoeffRange));
    }

    #[test]
    fn deterministic_healing_guard() {
        assert_eq!(
            check_deterministic_healing(&[0u8; D0_HEALING_SLOT_LEN]),
            Ok(())
        );
        let mut h = [0u8; D0_HEALING_SLOT_LEN];
        h[0] = 1;
        assert_eq!(
            check_deterministic_healing(&h),
            Err(D0Error::HealingNonzeroInDeterministicMode)
        );
    }
}