//! # AN-DNA xtask — Header generation and drift detection
//!
//! Usage:
//!   cargo run -p xtask -- gen-headers    # regenerate all headers
//!   cargo run -p xtask -- check-drift    # fail if headers are stale (CI)

use std::process::Command;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let cmd = args.get(1).map(|s| s.as_str()).unwrap_or("help");

    match cmd {
        "gen-headers" => gen_headers(),
        "check-drift" => check_drift(),
        _ => {
            eprintln!("Usage:");
            eprintln!("  cargo run -p xtask -- gen-headers    # regenerate headers");
            eprintln!("  cargo run -p xtask -- check-drift    # fail if headers stale (CI)");
            std::process::exit(1);
        }
    }
}

fn gen_headers() {
    println!("=== Generating andna_vnext_contracts.h ===");
    let status = Command::new("cargo")
        .args(["run", "-p", "contracts_codegen", "--", "generate"])
        .status()
        .expect("failed to run contracts_codegen");
    if !status.success() {
        eprintln!("contracts_codegen failed");
        std::process::exit(1);
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
        .expect("cbindgen not found — install with: cargo install cbindgen");
    if !status.success() {
        eprintln!("cbindgen failed");
        std::process::exit(1);
    }

    println!("\n✓ Headers regenerated.");
}

fn check_drift() {
    // Regenerate into temp, diff against committed
    println!("=== Checking for header drift ===");

    // Step 1: regenerate contracts header
    gen_headers();

    // Step 2: check git diff
    let output = Command::new("git")
        .args(["diff", "--exit-code", "include/"])
        .output()
        .expect("git diff failed");

    if !output.status.success() {
        eprintln!("\n✗ DRIFT DETECTED in include/");
        eprintln!("  Run `cargo run -p xtask -- gen-headers` and commit.");
        std::process::exit(1);
    }

    println!("\n✓ No drift detected.");
}
