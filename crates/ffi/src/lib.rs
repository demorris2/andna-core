//! # AN-DNA FFI — Stable C ABI shim
//!
//! This crate exposes the AN-DNA core verification functions via a stable
//! C ABI. It is the **only** crate in the workspace that uses `unsafe`.
//!
//! ABI rules:
//! - No heap ownership crosses the boundary
//! - All inputs are caller-owned
//! - Return enum only; no panics cross the boundary (catch_unwind)
//! - Generated header: include/andna_core.h (via cbindgen)

use andna_audit::{global_sink, init_sink_if_needed, VerifyEventInput};
use andna_contracts::*;
use andna_core::VerifyError;
use std::panic;
use std::time::{SystemTime, UNIX_EPOCH};

#[inline]
fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// C-compatible error codes.
///
/// cbindgen generates: ANDNA_ERR_OK, ANDNA_ERR_LENGTH, etc.
/// Integer values are ABI-stable and MUST NOT change.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AndnaErr {
    Ok = 0,
    Length = 1,
    MuPre = 2,
    Te = 3,
    Sig = 4,
    PkHashMismatch = 5,
    SigInvalid = 6,
    /// Directive B: mu_pre.epoch != T_E.epoch
    EpochMismatch = 7,
    /// Directive E: device_id32 != SHAKE256(device_id16, 32)
    DeviceIdMismatch = 8,
    /// Catch-all for panics caught at the FFI boundary (Directive C)
    Internal = 100,
}

impl From<VerifyError> for AndnaErr {
    fn from(e: VerifyError) -> Self {
        match e {
            VerifyError::LengthMismatch => AndnaErr::Length,
            VerifyError::MuPreMalformed => AndnaErr::MuPre,
            VerifyError::TeMalformed => AndnaErr::Te,
            VerifyError::SigMalformed => AndnaErr::Sig,
            VerifyError::PkHashMismatch => AndnaErr::PkHashMismatch,
            VerifyError::SignatureInvalid => AndnaErr::SigInvalid,
            VerifyError::EpochMismatch => AndnaErr::EpochMismatch,
            VerifyError::DeviceIdMismatch => AndnaErr::DeviceIdMismatch,
            VerifyError::Internal => AndnaErr::Internal,
        }
    }
}

// ── Directive C: catch_unwind wrapper ──
//
// Every extern "C" function must route through this so that a Rust panic
// never unwinds across the FFI boundary (which is Undefined Behavior).

/// Run `f` inside catch_unwind. On panic, return `AndnaErr::Internal`.
#[inline]
fn ffi_guard<F: FnOnce() -> AndnaErr + panic::UnwindSafe>(f: F) -> AndnaErr {
    match panic::catch_unwind(f) {
        Ok(result) => result,
        Err(_) => AndnaErr::Internal,
    }
}

/// Verify mu_pre + T_E + signature.
///
/// # Safety
/// - `mu_pre` must point to at least `mu_pre_len` readable bytes
/// - `te` must point to at least `te_len` readable bytes
/// - `sig` must point to at least `sig_len` readable bytes
/// - All pointers must be valid for the duration of the call
#[no_mangle]
pub unsafe extern "C" fn andna_verify_vnext(
    mu_pre: *const u8,
    mu_pre_len: usize,
    te: *const u8,
    te_len: usize,
    sig: *const u8,
    sig_len: usize,
) -> AndnaErr {
    // Null checks BEFORE catch_unwind (always safe)
    if mu_pre.is_null() || te.is_null() || sig.is_null() {
        return AndnaErr::Length;
    }
    if mu_pre_len != MU_PRE_LEN || te_len != TE_LEN || sig_len != SIG_LEN {
        return AndnaErr::Length;
    }

    // Copy raw pointers to local variables for UnwindSafe
    let mp = mu_pre;
    let t = te;
    let s = sig;

    ffi_guard(move || {
        let mu_pre_slice = unsafe { core::slice::from_raw_parts(mp, MU_PRE_LEN) };
        let te_slice = unsafe { core::slice::from_raw_parts(t, TE_LEN) };
        let sig_slice = unsafe { core::slice::from_raw_parts(s, SIG_LEN) };

        let mu_pre_arr: &[u8; MU_PRE_LEN] = match mu_pre_slice.try_into() {
            Ok(a) => a,
            Err(_) => return AndnaErr::Length,
        };
        let te_arr: &[u8; TE_LEN] = match te_slice.try_into() {
            Ok(a) => a,
            Err(_) => return AndnaErr::Length,
        };
        let sig_arr: &[u8; SIG_LEN] = match sig_slice.try_into() {
            Ok(a) => a,
            Err(_) => return AndnaErr::Length,
        };

        match andna_core::verify_vnext(mu_pre_arr, te_arr, sig_arr) {
            Ok(()) => AndnaErr::Ok,
            Err(e) => e.into(),
        }
    })
}

/// Verify a packed v2 frame (4030 bytes).
///
/// Gate 2 v1: Rust-owned audit sink appends one record per call.
///
/// # Safety
/// - `frame` must point to at least `frame_len` readable bytes
#[no_mangle]
pub unsafe extern "C" fn andna_verify_frame_v2(frame: *const u8, frame_len: usize) -> AndnaErr {
    if frame.is_null() || frame_len != FRAME_V2_LEN {
        return AndnaErr::Length;
    }

    let f = frame;

    ffi_guard(move || {
        let frame_slice = unsafe { core::slice::from_raw_parts(f, FRAME_V2_LEN) };

        // 1) Verify
        let res = andna_core::verify_frame_v2(frame_slice);
        let code: AndnaErr = match res {
            Ok(()) => AndnaErr::Ok,
            Err(e) => e.into(),
        };

        // 2) Gate 2: Rust-owned audit append (authoritative)
        // Fail closed if the sink mutex is poisoned.
        let decision: u8 = if code == AndnaErr::Ok { 1 } else { 0 };
        let err_code: i32 = code as i32;

        let sink = init_sink_if_needed(env!("CARGO_PKG_VERSION"));
        let mut guard = match sink.lock() {
            Ok(g) => g,
            Err(_) => return AndnaErr::Internal,
        };

        // notes_flags are enforced inside sink (HAS_FRAME, CRYPTO_REAL, reserved bits).
        guard.append_verify(VerifyEventInput {
            ts_unix_ms: now_unix_ms(),
            decision,
            engine: 1, // rust
            err_code,
            notes_flags: 0,
            frame_bytes: Some(frame_slice),
            frame_hash: None,
        });

        code
    })
}

/// Parse hot-path fields from mu_pre for pre-crypto gating.
///
/// # Safety
/// - `mu_pre` must point to at least `mu_pre_len` readable bytes
/// - `out_device_id32` must point to 32 writable bytes
/// - `out_epoch` must point to a valid u64
/// - `out_sid` must point to 32 writable bytes
#[no_mangle]
pub unsafe extern "C" fn andna_parse_mu_pre_header(
    mu_pre: *const u8,
    mu_pre_len: usize,
    out_device_id32: *mut u8,
    out_epoch: *mut u64,
    out_sid: *mut u8,
) -> AndnaErr {
    if mu_pre.is_null() || out_device_id32.is_null() || out_epoch.is_null() || out_sid.is_null() {
        return AndnaErr::Length;
    }
    if mu_pre_len != MU_PRE_LEN {
        return AndnaErr::Length;
    }

    let mp = mu_pre;
    let od = out_device_id32;
    let oe = out_epoch;
    let os = out_sid;

    ffi_guard(move || {
        let mu_pre_slice = unsafe { core::slice::from_raw_parts(mp, MU_PRE_LEN) };
        let mu_pre_arr: &[u8; MU_PRE_LEN] = match mu_pre_slice.try_into() {
            Ok(a) => a,
            Err(_) => return AndnaErr::Length,
        };

        match andna_codec::parse_mu_pre_header(mu_pre_arr) {
            Ok(hdr) => {
                unsafe {
                    core::ptr::copy_nonoverlapping(hdr.device_id32.as_ptr(), od, 32);
                    *oe = hdr.epoch;
                    core::ptr::copy_nonoverlapping(hdr.sid.as_ptr(), os, 32);
                }
                AndnaErr::Ok
            }
            Err(_) => AndnaErr::MuPre,
        }
    })
}

/// Generate a complete, validly-signed 4030-byte test frame (Frame v2).
///
/// Purpose: provide a real-signed frame so Python+Rust engines can agree on ACCEPT.
/// This is only meaningful when the real signature backend is enabled.
///
/// Keygen → build T_E → build mu_pre → sign μ → pack frame.
///
/// # Safety
/// - `out_ptr` must point to at least `out_len` writable bytes.
/// - `out_len` MUST equal FRAME_V2_LEN.
#[no_mangle]
pub unsafe extern "C" fn andna_gen_test_frame(out_ptr: *mut u8, out_len: usize) -> AndnaErr {
    // Safe checks before catch_unwind
    if out_ptr.is_null() || out_len != FRAME_V2_LEN {
        return AndnaErr::Length;
    }

    let outp = out_ptr;

    ffi_guard(move || {
        // Keep stub builds explicit: no real signing available.
        #[cfg(not(feature = "oqs-backend"))]
        {
            let _ = outp;
            return AndnaErr::Internal;
        }

        #[cfg(feature = "oqs-backend")]
        {
            use sha3::digest::{ExtendableOutput, Update, XofReader};
            use sha3::Shake256;

            // ── keygen ──────────────────────────────────────────────
            let scheme = match oqs::sig::Sig::new(oqs::sig::Algorithm::MlDsa44) {
                Ok(s) => s,
                Err(_) => return AndnaErr::Internal,
            };
            let (pk, sk) = match scheme.keypair() {
                Ok(p) => p,
                Err(_) => return AndnaErr::Internal,
            };

            let pk_bytes = pk.as_ref();
            let pk_core: usize = 32 + 1280; // rho + t1
            if pk_bytes.len() < pk_core {
                return AndnaErr::Internal;
            }

            // ── build T_E V1 (1336 bytes) ──────────────────────────
            let mut te = [0u8; TE_LEN];
            te[..pk_core].copy_from_slice(&pk_bytes[..pk_core]);

            let epoch: u64 = 1;
            te[TE_EPOCH_OFF..TE_EPOCH_OFF + 8].copy_from_slice(&epoch.to_le_bytes());

            let device_id16 = [0xBBu8; 16];
            te[TE_DEVICE_ID16_OFF..TE_DEVICE_ID16_OFF + 16].copy_from_slice(&device_id16);

            // ── derive device_id32 = SHAKE256(device_id16, 32) ─────
            let device_id32 = {
                let mut h = Shake256::default();
                h.update(&device_id16);
                let mut r = h.finalize_xof();
                let mut buf = [0u8; 32];
                r.read(&mut buf);
                buf
            };

            // ── build mu_pre (274 bytes) ───────────────────────────
            let mut mu_pre = [0u8; MU_PRE_LEN];

            // [0..64] pk_hash = SHAKE256(T_E, 64)
            {
                let mut h = Shake256::default();
                h.update(&te);
                let mut r = h.finalize_xof();
                r.read(&mut mu_pre[MU_PRE_PK_HASH_OFF..MU_PRE_PK_HASH_OFF + 64]);
            }

            // [64..73] domain_sep (9 bytes)
            mu_pre[MU_PRE_DOMAIN_SEP_OFF..MU_PRE_DOMAIN_SEP_OFF + MU_PRE_DOMAIN_SEP_LEN]
                .copy_from_slice(&DOMAIN_SEP_V1);

            // [73] version
            mu_pre[MU_PRE_VERSION_OFF] = 0x01u8;

            // [74..106] device_id32
            mu_pre[MU_PRE_DEVICE_ID32_OFF..MU_PRE_DEVICE_ID32_OFF + 32]
                .copy_from_slice(&device_id32);

            // [106..114] epoch LE
            mu_pre[MU_PRE_EPOCH_OFF..MU_PRE_EPOCH_OFF + 8].copy_from_slice(&epoch.to_le_bytes());

            // Remaining fields are left zero-filled for test/demo

            // ── compute μ = SHAKE256(mu_pre, 64) ───────────────────
            let mu = {
                let mut h = Shake256::default();
                h.update(&mu_pre);
                let mut r = h.finalize_xof();
                let mut buf = [0u8; 64];
                r.read(&mut buf);
                buf
            };

            // ── sign μ ─────────────────────────────────────────────
            let sig = match scheme.sign(&mu, &sk) {
                Ok(s) => s,
                Err(_) => return AndnaErr::Internal,
            };
            let sig_bytes = sig.as_ref();
            if sig_bytes.len() != SIG_LEN {
                return AndnaErr::Internal;
            }

            // ── pack frame ─────────────────────────────────────────
            let out = unsafe { core::slice::from_raw_parts_mut(outp, FRAME_V2_LEN) };
            out[0..MU_PRE_LEN].copy_from_slice(&mu_pre);
            out[MU_PRE_LEN..MU_PRE_LEN + TE_LEN].copy_from_slice(&te);
            out[MU_PRE_LEN + TE_LEN..FRAME_V2_LEN].copy_from_slice(sig_bytes);

            AndnaErr::Ok
        }
    })
}

/// Export the current Rust-owned audit log as deterministic JSONL.
///
/// # Safety
/// - `path` must be a valid NUL-terminated UTF-8 string pointer.
/// - The file will be overwritten.
#[no_mangle]
pub extern "C" fn andna_audit_export_jsonl(path: *const core::ffi::c_char) -> AndnaErr {
    if path.is_null() {
        return AndnaErr::Length;
    }

    let cstr = unsafe { core::ffi::CStr::from_ptr(path) };
    let out_path = match cstr.to_str() {
        Ok(s) => s,
        Err(_) => return AndnaErr::Length,
    };

    // Snapshot under lock, then export deterministically.
    let sink = global_sink();
    let guard = match sink.lock() {
        Ok(g) => g,
        Err(_) => return AndnaErr::Internal,
    };
    let records = guard.snapshot();
    drop(guard);

    let jsonl = andna_audit::export_jsonl::to_jsonl(&records);
    match std::fs::write(out_path, jsonl.as_bytes()) {
        Ok(_) => AndnaErr::Ok,
        Err(_) => AndnaErr::Internal,
    }
}

/// Return a human-readable error string for the given error code.
///
/// The returned pointer is a static `&str` — valid for the lifetime of the process.
/// Caller MUST NOT free it. This function cannot panic.
#[no_mangle]
pub extern "C" fn andna_strerror(err: AndnaErr) -> *const core::ffi::c_char {
    let msg: &[u8] = match err {
        AndnaErr::Ok => b"ok\0",
        AndnaErr::Length => b"length mismatch\0",
        AndnaErr::MuPre => b"mu_pre malformed\0",
        AndnaErr::Te => b"T_E malformed\0",
        AndnaErr::Sig => b"signature malformed\0",
        AndnaErr::PkHashMismatch => b"pk_hash binding mismatch\0",
        AndnaErr::SigInvalid => b"signature verification failed\0",
        AndnaErr::EpochMismatch => b"epoch mismatch between mu_pre and T_E\0",
        AndnaErr::DeviceIdMismatch => b"device_id32 != SHAKE256(device_id16)\0",
        AndnaErr::Internal => b"internal error (caught panic)\0",
    };
    msg.as_ptr() as *const core::ffi::c_char
}

/// Return the library version string (NUL-terminated).
///
/// The returned pointer is a static string — valid for the lifetime of the process.
/// This function cannot panic.
#[no_mangle]
pub extern "C" fn andna_version() -> *const core::ffi::c_char {
    concat!(env!("CARGO_PKG_VERSION"), "\0").as_ptr() as *const core::ffi::c_char
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ffi_verify_rejects_null() {
        unsafe {
            let r = andna_verify_vnext(
                core::ptr::null(),
                MU_PRE_LEN,
                core::ptr::null(),
                TE_LEN,
                core::ptr::null(),
                SIG_LEN,
            );
            assert_eq!(r, AndnaErr::Length);
        }
    }

    #[test]
    fn ffi_verify_rejects_wrong_length() {
        let mu = [0u8; MU_PRE_LEN];
        let te = [0u8; TE_LEN];
        let sig = [0u8; SIG_LEN];
        unsafe {
            let r =
                andna_verify_vnext(mu.as_ptr(), 100, te.as_ptr(), TE_LEN, sig.as_ptr(), SIG_LEN);
            assert_eq!(r, AndnaErr::Length);
        }
    }

    #[test]
    fn ffi_frame_rejects_null() {
        unsafe {
            assert_eq!(
                andna_verify_frame_v2(core::ptr::null(), FRAME_V2_LEN),
                AndnaErr::Length
            );
        }
    }

    #[test]
    fn ffi_frame_rejects_wrong_length() {
        let frame = [0u8; 100];
        unsafe {
            assert_eq!(andna_verify_frame_v2(frame.as_ptr(), 100), AndnaErr::Length);
        }
    }

    #[test]
    fn ffi_strerror_returns_valid_cstr() {
        let codes = [
            AndnaErr::Ok,
            AndnaErr::Length,
            AndnaErr::MuPre,
            AndnaErr::Te,
            AndnaErr::Sig,
            AndnaErr::PkHashMismatch,
            AndnaErr::SigInvalid,
            AndnaErr::EpochMismatch,
            AndnaErr::DeviceIdMismatch,
            AndnaErr::Internal,
        ];
        for code in codes {
            let ptr = andna_strerror(code);
            assert!(!ptr.is_null());
            let cstr = unsafe { core::ffi::CStr::from_ptr(ptr) };
            assert!(!cstr.to_str().unwrap().is_empty());
        }
    }

    #[test]
    fn ffi_version_returns_valid_cstr() {
        let ptr = andna_version();
        assert!(!ptr.is_null());
        let cstr = unsafe { core::ffi::CStr::from_ptr(ptr) };
        let ver = cstr.to_str().unwrap();
        assert!(
            ver.starts_with("0."),
            "version should start with '0.', got: {}",
            ver
        );
    }

    #[test]
    fn ffi_parse_mu_pre_rejects_null() {
        unsafe {
            let r = andna_parse_mu_pre_header(
                core::ptr::null(),
                MU_PRE_LEN,
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                core::ptr::null_mut(),
            );
            assert_eq!(r, AndnaErr::Length);
        }
    }

    // Only meaningful when real signing/verify is enabled.
    #[cfg(feature = "oqs-backend")]
    #[test]
    fn ffi_gen_test_frame_roundtrip() {
        let mut buf = vec![0u8; FRAME_V2_LEN];
        let rc = unsafe { andna_gen_test_frame(buf.as_mut_ptr(), buf.len()) };
        assert_eq!(rc, AndnaErr::Ok, "gen_test_frame failed with code {:?}", rc);

        let vrc = unsafe { andna_verify_frame_v2(buf.as_ptr(), buf.len()) };
        assert_eq!(
            vrc,
            AndnaErr::Ok,
            "verify rejected gen'd frame with code {:?}",
            vrc
        );
    }
}
