//! # AN-DNA xtask — Header generation, drift detection, and integrity reference generation
//!
//! Usage:
//!   cargo run -p xtask -- gen-headers
//!   cargo run -p xtask -- check-drift
//!   cargo run -p xtask -- write-integrity-reference <module.so> <out.integrity>

use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::Path;
use std::process::Command;

type HmacSha256 = Hmac<Sha256>;

const ANDNA_INTEGRITY_SCHEMA: &str = "ANDNA-INTEGRITY-v1";
const ANDNA_INTEGRITY_ARTIFACT: &str = "libandna_ffi.so";
const ANDNA_INTEGRITY_ALGORITHM: &str = "HMAC-SHA-256";
const ANDNA_INTEGRITY_KEY_ID: &str = "andna-r1-integrity-dev-v1";
const ANDNA_INTEGRITY_KEY_STATUS: &str = "non-secret-integrity-test-key";
const ANDNA_INTEGRITY_KEY: [u8; 32] = *b"ANDNA-R1-INTEGRITY-HMAC-KEY-0001";

fn main() {
    if let Err(err) = run() {
        eprintln!("{err}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let args: Vec<String> = std::env::args().collect();
    let cmd = args.get(1).map(|s| s.as_str()).unwrap_or("help");

    match cmd {
        "gen-headers" => gen_headers(),
        "check-drift" => check_drift(),
        "write-integrity-reference" => {
            let module_path = args.get(2).ok_or_else(|| {
                "usage: cargo run -p xtask -- write-integrity-reference <module.so> <out.integrity>"
                    .to_string()
            })?;

            let out_path = args.get(3).ok_or_else(|| {
                "usage: cargo run -p xtask -- write-integrity-reference <module.so> <out.integrity>"
                    .to_string()
            })?;

            if args.len() != 4 {
                return Err(
                    "usage: cargo run -p xtask -- write-integrity-reference <module.so> <out.integrity>"
                        .to_string(),
                );
            }

            write_integrity_reference(Path::new(module_path), Path::new(out_path))
        }
        "help" | "-h" | "--help" => {
            print_usage();
            Ok(())
        }
        other => {
            print_usage();
            Err(format!("unknown xtask command: {other}"))
        }
    }
}

fn print_usage() {
    eprintln!("Usage:");
    eprintln!("  cargo run -p xtask -- gen-headers");
    eprintln!("      Regenerate include/andna_vnext_contracts.h and include/andna_core.h");
    eprintln!();
    eprintln!("  cargo run -p xtask -- check-drift");
    eprintln!("      Regenerate headers and fail if include/ differs from committed state");
    eprintln!();
    eprintln!("  cargo run -p xtask -- write-integrity-reference <module.so> <out.integrity>");
    eprintln!("      Generate Path A' HMAC-SHA-256 integrity reference for a compiled module artifact");
}

fn to_hex32(bytes: &[u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";

    let mut out = String::with_capacity(64);
    for b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }

    out
}

fn sha256_bytes(bytes: &[u8]) -> [u8; 32] {
    let digest = Sha256::digest(bytes);
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

fn hmac_sha256_bytes(key: &[u8], bytes: &[u8]) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts keys of any length");
    mac.update(bytes);

    let digest = mac.finalize().into_bytes();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

fn write_integrity_reference(module_path: &Path, out_path: &Path) -> Result<(), String> {
    let bytes = fs::read(module_path)
        .map_err(|e| format!("failed to read module artifact {}: {e}", module_path.display()))?;

    let artifact_sha256 = sha256_bytes(&bytes);
    let tag = hmac_sha256_bytes(&ANDNA_INTEGRITY_KEY, &bytes);

    let reference = format!(
        "{schema}\n\
         artifact={artifact}\n\
         algorithm={algorithm}\n\
         key_id={key_id}\n\
         key_status={key_status}\n\
         tag_hex={tag_hex}\n\
         artifact_sha256={artifact_sha256_hex}\n",
        schema = ANDNA_INTEGRITY_SCHEMA,
        artifact = ANDNA_INTEGRITY_ARTIFACT,
        algorithm = ANDNA_INTEGRITY_ALGORITHM,
        key_id = ANDNA_INTEGRITY_KEY_ID,
        key_status = ANDNA_INTEGRITY_KEY_STATUS,
        tag_hex = to_hex32(&tag),
        artifact_sha256_hex = to_hex32(&artifact_sha256),
    );

    fs::write(out_path, reference)
        .map_err(|e| format!("failed to write integrity reference {}: {e}", out_path.display()))?;

    println!("Generated integrity reference:");
    println!("  module:          {}", module_path.display());
    println!("  reference:       {}", out_path.display());
    println!("  schema:          {}", ANDNA_INTEGRITY_SCHEMA);
    println!("  artifact:        {}", ANDNA_INTEGRITY_ARTIFACT);
    println!("  algorithm:       {}", ANDNA_INTEGRITY_ALGORITHM);
    println!("  key_id:          {}", ANDNA_INTEGRITY_KEY_ID);
    println!("  key_status:      {}", ANDNA_INTEGRITY_KEY_STATUS);
    println!("  artifact_sha256: {}", to_hex32(&artifact_sha256));
    println!("  tag_hex:         {}", to_hex32(&tag));

    Ok(())
}

fn gen_headers() -> Result<(), String> {
    println!("=== Generating andna_vnext_contracts.h ===");

    let status = Command::new("cargo")
        .args(["run", "-p", "contracts_codegen", "--", "generate"])
        .status()
        .map_err(|e| format!("failed to run contracts_codegen: {e}"))?;

    if !status.success() {
        return Err("contracts_codegen failed".to_string());
    }

    println!("=== Generating andna_core.h via cbindgen ===");

    let status = Command::new("cbindgen")
        .args([
            "--crate",
            "andna-ffi",
            "--config",
            "cbindgen.toml",
            "--output",
            "include/andna_core.h",
        ])
        .status()
        .map_err(|e| format!("cbindgen not found — install with: cargo install cbindgen: {e}"))?;

    if !status.success() {
        return Err("cbindgen failed".to_string());
    }

    println!("\n✓ Headers regenerated.");
    Ok(())
}

fn check_drift() -> Result<(), String> {
    println!("=== Checking for header drift ===");

    gen_headers()?;

    let output = Command::new("git")
        .args(["diff", "--exit-code", "include/"])
        .output()
        .map_err(|e| format!("git diff failed: {e}"))?;

    if !output.status.success() {
        eprintln!("\n✗ DRIFT DETECTED in include/");
        eprintln!("  Run `cargo run -p xtask -- gen-headers` and commit.");
        return Err(String::from_utf8_lossy(&output.stdout).to_string());
    }

    println!("\n✓ No drift detected.");
    Ok(())
}