use andna_contracts::{MU_PRE_DEVICE_ID32_LEN, PK_HASH_LEN, TE_DEVICE_ID16_LEN};

/// Facts R1 has already verified from a CRYPTO_ACCEPT frame.
///
/// R2 does not verify signatures. R2 consumes these facts only after Stage 1
/// verification succeeds.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedFacts {
    pub device_id16: [u8; TE_DEVICE_ID16_LEN],
    pub device_id32: [u8; MU_PRE_DEVICE_ID32_LEN],
    pub epoch: u64,
    pub te_hash: [u8; PK_HASH_LEN],
}

/// Stage 1 outcome passed into R2.
///
/// Fail-closed invariant:
///     CryptoReject can only produce NOT_EVALUATED.
///     Only CryptoAccept carries facts R2 may authorize over.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Stage1Outcome {
    CryptoAccept(VerifiedFacts),
    CryptoReject,
}
