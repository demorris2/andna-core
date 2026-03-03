//! # AN-DNA Codec — Strict parsing/packing for binary frames
//!
//! Zero-allocation, fixed-length frame parsing. No drift checks.
//! All length validation happens here; crypto happens elsewhere.

#![no_std]
#![forbid(unsafe_code)]

use andna_contracts::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CodecError {
    LengthMismatch,
    MuPreMalformed,
    TeMalformed,
    SigMalformed,
}

/// Parsed v2 frame — borrows into the original buffer, zero-copy.
#[derive(Debug, PartialEq)]
pub struct FrameV2Ref<'a> {
    pub mu_pre: &'a [u8; MU_PRE_LEN],
    pub te: &'a [u8; TE_LEN],
    pub sig: &'a [u8; SIG_LEN],
}

/// Hot-path fields from mu_pre (for gating before heavy crypto).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MuPreHeader {
    pub device_id32: [u8; 32],
    pub epoch: u64,
    pub sid: [u8; 32],
}

/// Metadata from T_E (for cache lookup / epoch gating).
#[derive(Debug, Clone, Copy)]
pub struct TeMeta {
    pub epoch: u64,
    pub device_id16: [u8; 16],
}

/// Parse a v2 binary frame (exactly 4030 bytes) into zero-copy refs.
pub fn unpack_frame_v2(frame: &[u8]) -> Result<FrameV2Ref<'_>, CodecError> {
    if frame.len() != FRAME_V2_LEN {
        return Err(CodecError::LengthMismatch);
    }
    let mu_pre: &[u8; MU_PRE_LEN] = frame[FRAME_V2_MU_PRE_OFF..FRAME_V2_MU_PRE_OFF + MU_PRE_LEN]
        .try_into().map_err(|_| CodecError::LengthMismatch)?;
    let te: &[u8; TE_LEN] = frame[FRAME_V2_TE_OFF..FRAME_V2_TE_OFF + TE_LEN]
        .try_into().map_err(|_| CodecError::LengthMismatch)?;
    let sig: &[u8; SIG_LEN] = frame[FRAME_V2_SIG_OFF..FRAME_V2_SIG_OFF + SIG_LEN]
        .try_into().map_err(|_| CodecError::LengthMismatch)?;
    Ok(FrameV2Ref { mu_pre, te, sig })
}

/// Parse hot-path fields from mu_pre for pre-crypto gating.
pub fn parse_mu_pre_header(mu_pre: &[u8; MU_PRE_LEN]) -> Result<MuPreHeader, CodecError> {
    if mu_pre[MU_PRE_VERSION_OFF] != MU_PRE_VERSION_VAL {
        return Err(CodecError::MuPreMalformed);
    }
    let ds = &mu_pre[MU_PRE_DOMAIN_SEP_OFF..MU_PRE_DOMAIN_SEP_OFF + MU_PRE_DOMAIN_SEP_LEN];
    if ds != DOMAIN_SEP.as_slice() {
        return Err(CodecError::MuPreMalformed);
    }

    let mut device_id32 = [0u8; 32];
    device_id32.copy_from_slice(
        &mu_pre[MU_PRE_DEVICE_ID32_OFF..MU_PRE_DEVICE_ID32_OFF + MU_PRE_DEVICE_ID32_LEN],
    );
    let mut epoch_bytes = [0u8; 8];
    epoch_bytes.copy_from_slice(
        &mu_pre[MU_PRE_EPOCH_OFF..MU_PRE_EPOCH_OFF + MU_PRE_EPOCH_LEN],
    );
    let mut sid = [0u8; 32];
    sid.copy_from_slice(
        &mu_pre[MU_PRE_SID_OFF..MU_PRE_SID_OFF + MU_PRE_SID_LEN],
    );

    Ok(MuPreHeader {
        device_id32,
        epoch: u64::from_le_bytes(epoch_bytes),
        sid,
    })
}

/// Parse metadata from T_E.
pub fn parse_te_meta(te: &[u8; TE_LEN]) -> Result<TeMeta, CodecError> {
    let mut epoch_bytes = [0u8; 8];
    epoch_bytes.copy_from_slice(&te[TE_EPOCH_OFF..TE_EPOCH_OFF + TE_EPOCH_LEN]);
    let mut device_id16 = [0u8; 16];
    device_id16.copy_from_slice(&te[TE_DEVICE_ID16_OFF..TE_DEVICE_ID16_OFF + TE_DEVICE_ID16_LEN]);
    Ok(TeMeta { epoch: u64::from_le_bytes(epoch_bytes), device_id16 })
}

/// Pack components into a v2 frame buffer.
pub fn pack_frame_v2(
    mu_pre: &[u8; MU_PRE_LEN],
    te: &[u8; TE_LEN],
    sig: &[u8; SIG_LEN],
    out: &mut [u8; FRAME_V2_LEN],
) {
    out[FRAME_V2_MU_PRE_OFF..FRAME_V2_MU_PRE_OFF + MU_PRE_LEN].copy_from_slice(mu_pre);
    out[FRAME_V2_TE_OFF..FRAME_V2_TE_OFF + TE_LEN].copy_from_slice(te);
    out[FRAME_V2_SIG_OFF..FRAME_V2_SIG_OFF + SIG_LEN].copy_from_slice(sig);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_valid_mu_pre() -> [u8; MU_PRE_LEN] {
        let mut buf = [0u8; MU_PRE_LEN];
        buf[MU_PRE_DOMAIN_SEP_OFF..MU_PRE_DOMAIN_SEP_OFF + DOMAIN_SEP_LEN]
            .copy_from_slice(&DOMAIN_SEP);
        buf[MU_PRE_VERSION_OFF] = MU_PRE_VERSION_VAL;
        buf[MU_PRE_EPOCH_OFF..MU_PRE_EPOCH_OFF + 8].copy_from_slice(&5u64.to_le_bytes());
        buf
    }

    #[test]
    fn rejects_wrong_length() {
        assert_eq!(unpack_frame_v2(&[0u8; 100]), Err(CodecError::LengthMismatch));
        assert_eq!(unpack_frame_v2(&[0u8; 4031]), Err(CodecError::LengthMismatch));
    }

    #[test]
    fn accepts_exact_length() {
        assert!(unpack_frame_v2(&[0u8; FRAME_V2_LEN]).is_ok());
    }

    #[test]
    fn roundtrip() {
        let mu = make_valid_mu_pre();
        let te = [0xABu8; TE_LEN];
        let sig = [0xCDu8; SIG_LEN];
        let mut frame = [0u8; FRAME_V2_LEN];
        pack_frame_v2(&mu, &te, &sig, &mut frame);
        let p = unpack_frame_v2(&frame).unwrap();
        assert_eq!(p.mu_pre, &mu);
        assert_eq!(p.te, &te);
        assert_eq!(p.sig, &sig);
    }

    #[test]
    fn mu_pre_header_epoch() {
        let mu = make_valid_mu_pre();
        assert_eq!(parse_mu_pre_header(&mu).unwrap().epoch, 5);
    }

    #[test]
    fn mu_pre_rejects_bad_version() {
        let mut mu = make_valid_mu_pre();
        mu[MU_PRE_VERSION_OFF] = 0xFF;
        assert_eq!(parse_mu_pre_header(&mu), Err(CodecError::MuPreMalformed));
    }

    #[test]
    fn te_meta_extraction() {
        let mut te = [0u8; TE_LEN];
        te[TE_EPOCH_OFF..TE_EPOCH_OFF + 8].copy_from_slice(&42u64.to_le_bytes());
        te[TE_DEVICE_ID16_OFF] = 0xDE;
        let m = parse_te_meta(&te).unwrap();
        assert_eq!(m.epoch, 42);
        assert_eq!(m.device_id16[0], 0xDE);
    }
}
