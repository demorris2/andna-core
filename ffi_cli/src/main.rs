//! # ffi_cli — command-line smoke test for AN-DNA FFI
//!
//! Usage:
//!   ffi-cli version                     Print library version
//!   ffi-cli verify-frame <hex>          Verify a hex-encoded 4030-byte frame
//!   ffi-cli verify-frame --file <path>  Verify a raw binary frame file
//!   ffi-cli smoke                       Run built-in smoke tests (stub mode)
//!
//! Exit codes:
//!   0  = success / verification passed
//!   1  = verification failed (with error name)
//!   2  = usage error

use andna_contracts::*;
use andna_ffi::*;
use std::{env, fs, process};

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        usage();
    }

    match args[1].as_str() {
        "version" => cmd_version(),
        "verify-frame" => cmd_verify_frame(&args[2..]),
        "smoke" => cmd_smoke(),
        _ => usage(),
    }
}

fn usage() -> ! {
    eprintln!("Usage: ffi-cli <version|verify-frame|smoke>");
    eprintln!("  version                     Print library version");
    eprintln!("  verify-frame <hex>          Verify hex-encoded frame");
    eprintln!("  verify-frame --file <path>  Verify binary frame file");
    eprintln!("  smoke                       Run built-in smoke tests");
    process::exit(2);
}

fn cmd_version() {
    let ptr = andna_version();
    let cstr = unsafe { std::ffi::CStr::from_ptr(ptr) };
    println!("andna-ffi {}", cstr.to_str().unwrap());
    process::exit(0);
}

fn cmd_verify_frame(args: &[String]) {
    if args.is_empty() {
        usage();
    }

    let frame_bytes = if args[0] == "--file" {
        if args.len() < 2 { usage(); }
        fs::read(&args[1]).unwrap_or_else(|e| {
            eprintln!("error: cannot read {}: {}", args[1], e);
            process::exit(2);
        })
    } else {
        hex_decode(&args[0])
    };

    let result = unsafe {
        andna_verify_frame_v2(frame_bytes.as_ptr(), frame_bytes.len())
    };

    let msg_ptr = andna_strerror(result);
    let msg = unsafe { std::ffi::CStr::from_ptr(msg_ptr) }.to_str().unwrap();

    if result == AndnaErr::Ok {
        println!("PASS: {}", msg);
        process::exit(0);
    } else {
        println!("FAIL ({}): {}", result as i32, msg);
        process::exit(1);
    }
}

fn cmd_smoke() {
    println!("=== AN-DNA FFI Smoke Tests ===\n");
    let mut pass = 0;
    let mut fail = 0;

    // Test 1: version
    {
        let ptr = andna_version();
        let cstr = unsafe { std::ffi::CStr::from_ptr(ptr) };
        let ver = cstr.to_str().unwrap();
        if !ver.is_empty() {
            println!("  [PASS] version: {}", ver);
            pass += 1;
        } else {
            println!("  [FAIL] version: empty");
            fail += 1;
        }
    }

    // Test 2: strerror roundtrip
    {
        let codes = [
            (AndnaErr::Ok, "ok"),
            (AndnaErr::Length, "length"),
            (AndnaErr::PkHashMismatch, "pk_hash"),
            (AndnaErr::SigInvalid, "signature verification"),
            (AndnaErr::EpochMismatch, "epoch"),
            (AndnaErr::DeviceIdMismatch, "device_id"),
        ];
        let mut ok = true;
        for (code, substr) in codes {
            let ptr = andna_strerror(code);
            let msg = unsafe { std::ffi::CStr::from_ptr(ptr) }.to_str().unwrap();
            if !msg.contains(substr) {
                println!("  [FAIL] strerror({:?}) = {:?}, expected substring {:?}", code, msg, substr);
                ok = false;
            }
        }
        if ok {
            println!("  [PASS] strerror: all codes map correctly");
            pass += 1;
        } else {
            fail += 1;
        }
    }

    // Test 3: null rejection
    {
        let r = unsafe { andna_verify_frame_v2(std::ptr::null(), 0) };
        if r == AndnaErr::Length {
            println!("  [PASS] null frame → ErrLength");
            pass += 1;
        } else {
            println!("  [FAIL] null frame → {:?}", r);
            fail += 1;
        }
    }

    // Test 4: wrong length rejection
    {
        let short = [0u8; 100];
        let r = unsafe { andna_verify_frame_v2(short.as_ptr(), 100) };
        if r == AndnaErr::Length {
            println!("  [PASS] short frame → ErrLength");
            pass += 1;
        } else {
            println!("  [FAIL] short frame → {:?}", r);
            fail += 1;
        }
    }

    // Test 5: well-formed frame (all directives satisfied, zero signature)
    //   - stub backend: sig verify always passes → Ok
    //   - oqs-backend: zero sig is invalid → ErrSigInvalid
    //   Both outcomes mean the plumbing works correctly.
    {
        let mut frame = vec![0u8; FRAME_V2_LEN];
        use sha3::digest::{ExtendableOutput, Update, XofReader};

        // T_E is all zeros: epoch=0, device_id16=0x00×16

        // Set pk_hash = SHAKE256(zeros_te, 64)
        let te_slice = &frame[MU_PRE_LEN..MU_PRE_LEN + TE_LEN];
        let mut hasher = sha3::Shake256::default();
        hasher.update(te_slice);
        let mut reader = hasher.finalize_xof();
        reader.read(&mut frame[0..PK_HASH_LEN]);

        // Directive A: set domain separator + version
        frame[MU_PRE_DOMAIN_SEP_OFF..MU_PRE_DOMAIN_SEP_OFF + DOMAIN_SEP_LEN]
            .copy_from_slice(&DOMAIN_SEP);
        frame[MU_PRE_VERSION_OFF] = MU_PRE_VERSION_VAL;

        // Directive B: epoch in mu_pre must match T_E epoch (both are 0, ok)

        // Directive E: device_id32 = SHAKE256(device_id16, 32)
        // device_id16 = zeros (from T_E)
        let device_id16 = &[0u8; TE_DEVICE_ID16_LEN];
        let mut id32_hasher = sha3::Shake256::default();
        id32_hasher.update(device_id16);
        let mut id32_reader = id32_hasher.finalize_xof();
        id32_reader.read(&mut frame[MU_PRE_DEVICE_ID32_OFF..MU_PRE_DEVICE_ID32_OFF + MU_PRE_DEVICE_ID32_LEN]);

        let r = unsafe { andna_verify_frame_v2(frame.as_ptr(), frame.len()) };
        if r == AndnaErr::Ok {
            println!("  [PASS] well-formed frame → Ok (stub backend)");
            pass += 1;
        } else if r == AndnaErr::SigInvalid {
            println!("  [PASS] well-formed frame → ErrSigInvalid (real ML-DSA-44 backend)");
            pass += 1;
        } else {
            let msg_ptr = andna_strerror(r);
            let msg = unsafe { std::ffi::CStr::from_ptr(msg_ptr) }.to_str().unwrap();
            println!("  [FAIL] well-formed frame → {:?} ({})", r, msg);
            fail += 1;
        }
    }

    // Test 6: zeroed frame → Directive A catches missing domain sep/version
    {
        let frame = vec![0u8; FRAME_V2_LEN]; // domain sep = zeros → MuPre error
        let r = unsafe { andna_verify_frame_v2(frame.as_ptr(), frame.len()) };
        if r == AndnaErr::MuPre {
            println!("  [PASS] zeroed frame → ErrMuPre (Directive A: domain sep)");
            pass += 1;
        } else {
            println!("  [FAIL] zeroed frame → {:?}", r);
            fail += 1;
        }
    }

    println!("\n=== Results: {} passed, {} failed ===", pass, fail);
    process::exit(if fail > 0 { 1 } else { 0 });
}

fn hex_decode(s: &str) -> Vec<u8> {
    let s = s.trim();
    if !s.len().is_multiple_of(2) {
        eprintln!("error: hex string has odd length");
        process::exit(2);
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap_or_else(|_| {
            eprintln!("error: invalid hex at position {}", i);
            process::exit(2);
        }))
        .collect()
}
