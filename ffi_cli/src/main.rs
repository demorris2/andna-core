//! # andna — Rust-owned end-user proof CLI for AN-DNA R1
//!
//! This promotes the Rust path from smoke tester to the full operator workflow.
//! The Rust FFI remains the authoritative verification kernel, and this binary
//! now owns the user-facing proof flow:
//!   gen → verify → tamper → verify → replay → export
//!
//! Backward compatibility:
//! - `version`, `verify-frame`, and `smoke` are preserved.
//!
//! Exit codes:
//!   0 = success / verification passed
//!   1 = verification failed / tamper detected / mismatch
//!   2 = usage / file / parsing error

use andna_contracts::*;
use andna_ffi::*;
use andna_seal::{seal_file, verify_sealed, Registry, SealedBundle, SoftwareProfileSigner};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};
use std::{
    env,
    ffi::CStr,
    fs, io,
    path::{Path, PathBuf},
    process,
    time::{SystemTime, UNIX_EPOCH},
};

const LOG_PATH: &str = "verification_log.json";
const EVIDENCE_SCHEMA_VERSION: &str = "1.1.0";
const CONTRACT_VERSION: &str = "vNext-Phase1-R1";
const ENGINE_NAME: &str = "rust";

#[derive(Debug, Clone, Serialize, Deserialize)]
struct VerificationRecord {
    run_id: String,
    timestamp: String,
    frame_hash: String,
    frame_len: usize,
    decision: String,
    error_code: i32,
    error_msg: Option<String>,
    engine: String,
    contract_version: String,
    schema_version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ReplayFile {
    schema_version: String,
    contract_version: String,
    record_count: usize,
    records: Vec<VerificationRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct EvidenceManifest {
    schema_version: String,
    contract_version: String,
    record_count: usize,
    evidence_file: String,
    evidence_digest: String,
    digest_algorithm: String,
    verification_digest: String,
    generated_at: String,
}

#[derive(Debug, Clone, Serialize)]
struct CliRegistryFile {
    snapshot_seq: u64,
    as_of_unix_ms: u64,
    policy_version: String,
    entries: Vec<CliRegistryEntry>,
}

#[derive(Debug, Clone, Serialize)]
struct CliRegistryEntry {
    device_id16_hex: String,
    device_id32_hex: String,
    authorized_te_hashes_hex: Vec<String>,
    current_epoch: u64,
    revoked: bool,
    frozen: bool,
    recovery_hold: bool,
    policy_version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CliSealerProfile {
    schema_version: String,
    profile_type: String,
    seed_hex: String,
    device_id16_hex: String,
    epoch: u64,
    created_at_unix_ms: u64,
    warning: String,
}

impl CliSealerProfile {
    fn to_signer(&self) -> Result<SoftwareProfileSigner, String> {
        if self.schema_version != "andna-sealer-profile-v0" {
            return Err(format!(
                "unsupported sealer profile schema: {}",
                self.schema_version
            ));
        }

        if self.profile_type != "software-profile" {
            return Err(format!(
                "unsupported sealer profile type: {}",
                self.profile_type
            ));
        }

        let seed = parse_hex_array::<32>(&self.seed_hex, "profile.seed_hex")?;
        let device_id16 = parse_hex_array::<TE_DEVICE_ID16_LEN>(
            &self.device_id16_hex,
            "profile.device_id16_hex",
        )?;

        Ok(SoftwareProfileSigner::from_seed(
            seed,
            device_id16,
            self.epoch,
        ))
    }
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        usage();
    }

    let rc = match args[1].as_str() {
        "version" => {
            cmd_version();
            0
        }
        "verify" => cmd_verify(&args[2..]),
        "replay" => cmd_replay(&args[2..]),
        "export" => cmd_export(&args[2..]),
        "gen" => cmd_gen(&args[2..]),
        "tamper" => cmd_tamper(&args[2..]),
        "init-sealer" => cmd_init_sealer(&args[2..]),
        "seal-file" => cmd_seal_file(&args[2..]),
        "verify-file" => cmd_verify_file(&args[2..]),
        // Backward-compatible legacy commands
        "verify-frame" => cmd_verify_frame_legacy(&args[2..]),
        "smoke" => cmd_smoke(),
        "--help" | "-h" | "help" => {
            usage();
        }
        _ => {
            eprintln!("Unknown command or wrong arguments: {}", args[1]);
            usage();
        }
    };
    process::exit(rc);
}

fn usage() -> ! {
    eprintln!("AN-DNA vNext — Deterministic Replay CLI (Rust authoritative path)\n");
    eprintln!("Usage:");
    eprintln!("    andna verify   <frame.bin>               Verify a binary frame");
    eprintln!("    andna replay   <log.json>                Replay and validate decisions");
    eprintln!(
        "    andna replay   <log.json> --frame <f.bin> Re-verify frame, assert same decision"
    );
    eprintln!("    andna export   <output_dir>              Export evidence bundle");
    eprintln!("    andna gen      <output.bin>              Generate valid sample frame");
    eprintln!("    andna tamper   <input.bin> <output.bin>  Flip one byte to create a reject");
    eprintln!("\nLegacy:");
    eprintln!("    andna version");
    eprintln!("    andna verify-frame <hex>");
    eprintln!("    andna verify-frame --file <path>");
    eprintln!("    andna smoke");
    eprintln!("\n5-Minute Demo:");
    eprintln!("    andna gen sample_frame.bin");
    eprintln!("    andna verify sample_frame.bin");
    eprintln!("    andna tamper sample_frame.bin tampered_frame.bin");
    eprintln!("    andna verify tampered_frame.bin");
    eprintln!("    andna replay verification_log.json");
    eprintln!("    andna replay verification_log.json --frame sample_frame.bin");
    eprintln!("    andna export evidence/");
    eprintln!("    andna init-sealer --profile <profile.json> [--epoch <n>]");
    eprintln!("    andna seal-file <file> --profile <profile.json> --out <seal.json> [--content-type <mime>] [--registry-out <registry.json>]");
    eprintln!("    andna seal-file <file> --out <seal.json> --seed-hex <64hex> --device-id16-hex <32hex> [--epoch <n>] [--content-type <mime>] [--registry-out <registry.json>]");
    eprintln!("    andna verify-file <file> --seal <seal.json> --registry <registry.json> [--evidence-out <result.json>]");
    eprintln!("    andna seal-file sample.txt --out sample.txt.andna-seal.json --seed-hex <64hex> --device-id16-hex <32hex> --epoch 7 --registry-out sample.registry.json");
    eprintln!("    andna verify-file sample.txt --seal sample.txt.andna-seal.json --registry sample.registry.json");
    process::exit(2);
}

fn cmd_version() {
    let ptr = andna_version();
    let cstr = unsafe { CStr::from_ptr(ptr) };
    println!("andna {}", cstr.to_str().unwrap_or("unknown"));
}

fn ensure_andna_init() -> Result<(), String> {
    let rc = andna_ffi::andna_init();

    if rc == AndnaErr::Ok {
        Ok(())
    } else {
        Err(format!("andna_init failed: {:?} ({})", rc, strerror(rc)))
    }
}

fn cmd_verify(args: &[String]) -> i32 {
    if args.len() != 1 {
        usage();
    }

    let path = Path::new(&args[0]);
    let frame = match fs::read(path) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("error: cannot read {}: {}", path.display(), e);
            return 2;
        }
    };

    if let Err(e) = ensure_andna_init() {
        eprintln!("error: {}", e);
        return 1;
    }

    let start = std::time::Instant::now();
    let err = unsafe { andna_verify_frame_v2(frame.as_ptr(), frame.len()) };
    let duration_ms = start.elapsed().as_secs_f64() * 1000.0;

    let frame_hash = sha3_256_hex(&frame);
    let ok = err == AndnaErr::Ok;
    let decision = if ok { "ACCEPT" } else { "REJECT" };
    let error_code = err as i32;
    let error_msg = if ok { None } else { Some(strerror(err)) };

    let mut log = load_log(Path::new(LOG_PATH)).unwrap_or_else(|_| ReplayFile::new());
    let record = VerificationRecord {
        run_id: format!("run-{}", now_nanos()),
        timestamp: now_timestamp(),
        frame_hash: frame_hash.clone(),
        frame_len: frame.len(),
        decision: decision.to_string(),
        error_code,
        error_msg: error_msg.clone(),
        engine: ENGINE_NAME.to_string(),
        contract_version: CONTRACT_VERSION.to_string(),
        schema_version: EVIDENCE_SCHEMA_VERSION.to_string(),
    };
    log.records.push(record.clone());
    log.record_count = log.records.len();

    if let Err(e) = save_log(Path::new(LOG_PATH), &log) {
        eprintln!("error: failed to persist {}: {}", LOG_PATH, e);
        return 2;
    }

    // Flush the Rust authoritative FFI sink to disk (safely without the unsafe wrapper)
    if let Ok(c_path) = std::ffi::CString::new("andna_audit.jsonl") {
        andna_audit_export_jsonl(c_path.as_ptr());
    }

    print_verify_result(path, &frame_hash, &record, duration_ms);
    if ok {
        0
    } else {
        1
    }
}

fn cmd_replay(args: &[String]) -> i32 {
    if args.is_empty() {
        usage();
    }

    let log_path = Path::new(&args[0]);
    let replay = match load_log(log_path) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("error: cannot load {}: {}", log_path.display(), e);
            return 2;
        }
    };
    if replay.records.is_empty() {
        eprintln!("error: no records in {}", log_path.display());
        return 2;
    }

    let frame_arg = if args.len() == 3 && args[1] == "--frame" {
        Some(PathBuf::from(&args[2]))
    } else if args.len() == 1 {
        None
    } else {
        usage();
    };

    print_replay_header(log_path, &replay);

    if let Some(frame_path) = frame_arg {
        return replay_with_frame(&replay, &frame_path);
    }

    let mut all_valid = true;
    println!("────────────────────────────────────────────────────────────");
    for (idx, rec) in replay.records.iter().enumerate() {
        println!("\n  Record {}/{}", idx + 1, replay.records.len());
        kv(3, "Run ID", &rec.run_id);
        kv(3, "Decision", &rec.decision);
        kv(3, "Frame hash", &rec.frame_hash);
        kv(3, "Error code", &rec.error_code.to_string());
        kv(3, "Engine", &rec.engine);
        kv(3, "Contract", &rec.contract_version);

        if !rec.run_id.starts_with("run-") || rec.frame_hash.len() != 64 {
            println!("      ⚠  Record structure invalid");
            all_valid = false;
        } else {
            println!("      ✓  Record structure valid");
        }
    }
    println!("────────────────────────────────────────────────────────────");

    if all_valid {
        println!(
            "\n  ✓ Replay verified: {} record(s), all structurally valid.",
            replay.records.len()
        );
        println!("  Determinism claim: same frame → same hash → same decision.");
        println!("  To fully verify: `andna replay <log> --frame <frame.bin>`\n");
        0
    } else {
        println!("\n  ✗ Replay has structural issues. See warnings above.\n");
        1
    }
}

fn replay_with_frame(replay: &ReplayFile, frame_path: &Path) -> i32 {
    let frame = match fs::read(frame_path) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("error: cannot read {}: {}", frame_path.display(), e);
            return 2;
        }
    };
    let frame_hash = sha3_256_hex(&frame);
    let Some(rec) = replay.records.iter().find(|r| r.frame_hash == frame_hash) else {
        println!("────────────────────────────────────────────────────────────");
        println!(
            "\n  ✗ No record matches frame hash {}...",
            &frame_hash[..16]
        );
        println!("    Frame may not be from this verification session.\n");
        return 1;
    };

    if let Err(e) = ensure_andna_init() {
        eprintln!("error: {}", e);
        return 1;
    }

    let err = unsafe { andna_verify_frame_v2(frame.as_ptr(), frame.len()) };
    let new_decision = if err == AndnaErr::Ok {
        "ACCEPT"
    } else {
        "REJECT"
    };

    println!("────────────────────────────────────────────────────────────");
    println!("\n  Re-verifying frame: {}", frame_path.display());
    kv(3, "Frame digest", &frame_hash);
    kv(3, "Recorded decision", &rec.decision);
    kv(3, "Re-verify decision", new_decision);
    kv(3, "Re-verify engine", ENGINE_NAME);

    if new_decision == rec.decision {
        println!("\n      ✓ Deterministic: same frame → same decision");
        println!(
            "        Recorded: {}  |  Re-verified: {}\n",
            rec.decision, new_decision
        );
        0
    } else {
        println!("\n      ✗ NON-DETERMINISTIC: decisions differ!");
        println!(
            "        Recorded: {}  |  Re-verified: {}\n",
            rec.decision, new_decision
        );
        1
    }
}

fn cmd_export(args: &[String]) -> i32 {
    if args.len() != 1 {
        usage();
    }

    let log = match load_log(Path::new(LOG_PATH)) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("error: cannot load {}: {}", LOG_PATH, e);
            return 2;
        }
    };
    if log.records.is_empty() {
        eprintln!("error: no session records to export");
        return 2;
    }

    let output_dir = Path::new(&args[0]);
    if let Err(e) = fs::create_dir_all(output_dir) {
        eprintln!("error: cannot create {}: {}", output_dir.display(), e);
        return 2;
    }

    let evidence_path = output_dir.join("evidence.json");
    let manifest_path = output_dir.join("manifest.json");

    if let Err(e) = save_log(&evidence_path, &log) {
        eprintln!("error: cannot write {}: {}", evidence_path.display(), e);
        return 2;
    }

    // Export Gate 2 Artifacts (Authoritative Log + Validator output)
    let audit_src = Path::new("andna_audit.jsonl");
    let mut val_json = format!(
        "{{\n  \"status\": \"FAIL\",\n  \"error\": \"No audit log found\",\n  \"records_validated\": 0,\n  \"chain_hash_algorithm\": \"sha3-256\"\n}}"
    );

    if audit_src.exists() {
        let bundle_audit = output_dir.join("andna_audit.jsonl");
        if let Err(e) = fs::copy(audit_src, &bundle_audit) {
            eprintln!("error: cannot copy audit log: {}", e);
        } else if let Ok(content) = fs::read_to_string(audit_src) {
            let records_validated = content.lines().filter(|l| !l.trim().is_empty()).count();

            // Actually run the validator!
            match andna_audit::validate_jsonl(&content) {
                Ok(_) => {
                    val_json = format!(
                        "{{\n  \"status\": \"PASS\",\n  \"records_validated\": {},\n  \"chain_hash_algorithm\": \"sha3-256\"\n}}",
                        records_validated
                    );
                }
                Err(e) => {
                    val_json = format!(
                        "{{\n  \"status\": \"FAIL\",\n  \"error\": \"{:?}\",\n  \"records_validated\": {},\n  \"chain_hash_algorithm\": \"sha3-256\"\n}}",
                        e, records_validated
                    );
                }
            }
        }
    }

    if let Err(e) = fs::write(output_dir.join("audit_validate.json"), val_json) {
        eprintln!("error: cannot write audit_validate.json: {}", e);
    }

    let evidence_bytes = match fs::read(&evidence_path) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("error: cannot read {}: {}", evidence_path.display(), e);
            return 2;
        }
    };

    let manifest = EvidenceManifest {
        schema_version: EVIDENCE_SCHEMA_VERSION.to_string(),
        contract_version: CONTRACT_VERSION.to_string(),
        record_count: log.records.len(),
        evidence_file: "evidence.json".to_string(),
        evidence_digest: sha3_256_hex(&evidence_bytes),
        digest_algorithm: "sha3-256".to_string(),
        verification_digest: compute_verification_digest(&log.records),
        generated_at: now_timestamp(),
    };

    let manifest_bytes = to_pretty_json(&manifest).into_bytes();
    if let Err(e) = fs::write(&manifest_path, manifest_bytes) {
        eprintln!("error: cannot write {}: {}", manifest_path.display(), e);
        return 2;
    }

    print_export_result(output_dir, &manifest);
    0
}

fn cmd_gen(args: &[String]) -> i32 {
    if args.len() != 1 {
        usage();
    }
    let output = Path::new(&args[0]);
    let mut frame = vec![0u8; FRAME_V2_LEN];

    if let Err(e) = ensure_andna_init() {
        eprintln!("error: {}", e);
        return 1;
    }

    let rc = unsafe { andna_gen_test_frame(frame.as_mut_ptr(), frame.len()) };
    if rc != AndnaErr::Ok {
        eprintln!("error: andna_gen_test_frame failed: {}", strerror(rc));
        eprintln!("hint: build the Rust CLI with the real ML-DSA backend enabled.");
        return 1;
    }
    if let Err(e) = fs::write(output, &frame) {
        eprintln!("error: cannot write {}: {}", output.display(), e);
        return 2;
    }

    println!("\n============================================================");
    println!("  AN-DNA Sample Frame Generated (Rust authoritative path)");
    println!("============================================================");
    kv(4, "Output", &output.display().to_string());
    kv(4, "Size", &format!("{} bytes", frame.len()));
    kv(4, "Frame digest", &sha3_256_hex(&frame));
    kv(4, "Expected decision", "ACCEPT (real ML-DSA backend)");
    println!();
    0
}

fn cmd_tamper(args: &[String]) -> i32 {
    if args.len() != 2 {
        usage();
    }
    let input = Path::new(&args[0]);
    let output = Path::new(&args[1]);

    let mut frame = match fs::read(input) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("error: cannot read {}: {}", input.display(), e);
            return 2;
        }
    };
    if frame.is_empty() {
        eprintln!("error: {} is empty", input.display());
        return 2;
    }

    let before = frame[0];
    frame[0] ^= 0xFF;
    if let Err(e) = fs::write(output, &frame) {
        eprintln!("error: cannot write {}: {}", output.display(), e);
        return 2;
    }

    println!("\n════════════════════════════════════════════════════════════");
    println!("  AN-DNA Frame Tampered");
    println!("════════════════════════════════════════════════════════════");
    kv(4, "Input", &input.display().to_string());
    kv(4, "Output", &output.display().to_string());
    kv(
        4,
        "Tampered byte",
        &format!("offset 0: 0x{:02X} → 0x{:02X}", before, frame[0]),
    );
    kv(4, "Expected decision", "REJECT");
    println!();
    0
}

fn cmd_init_sealer(args: &[String]) -> i32 {
    let Some(profile_path) = opt_value(args, "--profile") else {
        eprintln!("error: init-sealer requires --profile <profile.json>");
        return 2;
    };

    let epoch = match opt_value(args, "--epoch") {
        Some(s) => match s.parse::<u64>() {
            Ok(v) => v,
            Err(e) => {
                eprintln!("error: invalid --epoch value {}: {}", s, e);
                return 2;
            }
        },
        None => 7,
    };

    let seed = match random_array::<32>() {
        Ok(v) => v,
        Err(e) => {
            eprintln!("error: could not generate seed: {}", e);
            return 2;
        }
    };

    let device_id16 = match random_array::<TE_DEVICE_ID16_LEN>() {
        Ok(v) => v,
        Err(e) => {
            eprintln!("error: could not generate device_id16: {}", e);
            return 2;
        }
    };

    let profile = CliSealerProfile {
        schema_version: "andna-sealer-profile-v0".to_string(),
        profile_type: "software-profile".to_string(),
        seed_hex: hex::encode(seed),
        device_id16_hex: hex::encode(device_id16),
        epoch,
        created_at_unix_ms: now_unix_ms(),
        warning: "Software-profile demo credential. Contains signing seed material. Do not commit, share, or use as hardware-backed custody proof.".to_string(),
    };

    let path = Path::new(&profile_path);

    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            if let Err(e) = fs::create_dir_all(parent) {
                eprintln!(
                    "error: cannot create profile directory {}: {}",
                    parent.display(),
                    e
                );
                return 2;
            }
        }
    }

    let json =
        serde_json::to_string_pretty(&profile).expect("CLI sealer profile is always serializable");

    if let Err(e) = fs::write(path, json) {
        eprintln!("error: cannot write profile {}: {}", path.display(), e);
        return 2;
    }

    println!("\n════════════════════════════════════════════════════════════");
    println!("  AN-DNA Software-Profile Sealer Created");
    println!("════════════════════════════════════════════════════════════");
    kv(4, "Profile", &path.display().to_string());
    kv(4, "Profile type", "software-profile");
    kv(4, "Epoch", &epoch.to_string());
    println!("────────────────────────────────────────────────────────────");
    println!("  Warning: profile contains seed material. Do not commit or share.");
    println!("  Scope: software-profile only; not hardware custody or clone resistance.");
    println!();

    0
}

fn cmd_seal_file(args: &[String]) -> i32 {
    if args.is_empty() {
        usage();
    }

    let input = Path::new(&args[0]);

    let Some(out_path) = opt_value(args, "--out") else {
        eprintln!("error: seal-file requires --out <seal.json>");
        return 2;
    };

    let content_type = opt_value(args, "--content-type");
    let registry_out = opt_value(args, "--registry-out");

    let (signer, signer_source, signer_epoch) = if let Some(profile_path) =
        opt_value(args, "--profile")
    {
        if opt_value(args, "--seed-hex").is_some() || opt_value(args, "--device-id16-hex").is_some()
        {
            eprintln!("error: use either --profile or --seed-hex/--device-id16-hex, not both");
            return 2;
        }

        if opt_value(args, "--epoch").is_some() {
            eprintln!("error: --epoch is stored in the sealer profile when --profile is used");
            return 2;
        }

        let raw = match fs::read_to_string(&profile_path) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("error: cannot read profile {}: {}", profile_path, e);
                return 2;
            }
        };

        let profile: CliSealerProfile = match serde_json::from_str(&raw) {
            Ok(p) => p,
            Err(e) => {
                eprintln!("error: cannot parse profile {}: {}", profile_path, e);
                return 2;
            }
        };

        let epoch = profile.epoch;

        let signer = match profile.to_signer() {
            Ok(s) => s,
            Err(e) => {
                eprintln!("error: invalid sealer profile {}: {}", profile_path, e);
                return 2;
            }
        };

        (signer, format!("profile: {}", profile_path), epoch)
    } else {
        let Some(seed_hex) = opt_value(args, "--seed-hex") else {
            eprintln!(
                "error: seal-file requires either --profile <profile.json> or --seed-hex <64 hex chars>"
            );
            return 2;
        };

        let Some(device_id16_hex) = opt_value(args, "--device-id16-hex") else {
            eprintln!(
                "error: seal-file requires --device-id16-hex <32 hex chars> when --profile is not used"
            );
            return 2;
        };

        let epoch = match opt_value(args, "--epoch") {
            Some(s) => match s.parse::<u64>() {
                Ok(v) => v,
                Err(e) => {
                    eprintln!("error: invalid --epoch value {}: {}", s, e);
                    return 2;
                }
            },
            None => 7,
        };

        let seed = match parse_hex_array::<32>(&seed_hex, "seed-hex") {
            Ok(v) => v,
            Err(e) => {
                eprintln!("error: {}", e);
                return 2;
            }
        };

        let device_id16 =
            match parse_hex_array::<TE_DEVICE_ID16_LEN>(&device_id16_hex, "device-id16-hex") {
                Ok(v) => v,
                Err(e) => {
                    eprintln!("error: {}", e);
                    return 2;
                }
            };

        (
            SoftwareProfileSigner::from_seed(seed, device_id16, epoch),
            "manual seed/device flags".to_string(),
            epoch,
        )
    };

    let file_bytes = match fs::read(input) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("error: cannot read {}: {}", input.display(), e);
            return 2;
        }
    };

    let file_name = input
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or_else(|| input.to_str().unwrap_or("sealed-file"))
        .to_string();

    let bundle = seal_file(file_name, &file_bytes, content_type, &signer);

    let out = Path::new(&out_path);
    if let Err(e) = fs::write(out, bundle.to_json_pretty()) {
        eprintln!("error: cannot write {}: {}", out.display(), e);
        return 2;
    }

    println!("\n════════════════════════════════════════════════════════════");
    println!("  AN-DNA File Seal Created");
    println!("════════════════════════════════════════════════════════════");
    kv(4, "Input file", &input.display().to_string());
    kv(4, "Seal sidecar", &out.display().to_string());
    kv(4, "Signer source", &signer_source);
    kv(
        4,
        "Manifest hash",
        &hex::encode(bundle.manifest.manifest_hash()),
    );
    kv(4, "File hash", &bundle.manifest.file_hash_hex);
    kv(4, "Frame encoding", &bundle.frame_encoding);
    kv(4, "Epoch", &signer_epoch.to_string());
    println!("────────────────────────────────────────────────────────────");
    println!("  Scope: integrity/authenticity binding only; this does NOT encrypt the file.");

    if let Some(reg_path) = registry_out {
        if let Err(e) = write_registry_for_bundle(&bundle, Path::new(&reg_path)) {
            eprintln!("error: cannot write registry {}: {}", reg_path, e);
            return 2;
        }
        kv(4, "Registry", &reg_path);
    }

    println!();
    0
}

fn cmd_verify_file(args: &[String]) -> i32 {
    if args.is_empty() {
        usage();
    }

    let input = Path::new(&args[0]);

    let Some(seal_path) = opt_value(args, "--seal") else {
        eprintln!("error: verify-file requires --seal <seal.json>");
        return 2;
    };

    let Some(registry_path) = opt_value(args, "--registry") else {
        eprintln!("error: verify-file requires --registry <registry.json>");
        return 2;
    };

    let evidence_out = opt_value(args, "--evidence-out");

    let file_bytes = match fs::read(input) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("error: cannot read {}: {}", input.display(), e);
            return 2;
        }
    };

    let seal_raw = match fs::read_to_string(&seal_path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("error: cannot read seal {}: {}", seal_path, e);
            return 2;
        }
    };

    let bundle: SealedBundle = match serde_json::from_str(&seal_raw) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("error: cannot parse seal {}: {}", seal_path, e);
            return 2;
        }
    };

    let registry_raw = match fs::read_to_string(&registry_path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("error: cannot read registry {}: {}", registry_path, e);
            return 2;
        }
    };

    let registry = match Registry::from_json(&registry_raw) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("error: cannot parse registry {}: {:?}", registry_path, e);
            return 2;
        }
    };

    let result = verify_sealed(&bundle, &file_bytes, &registry);

    println!("\n════════════════════════════════════════════════════════════");
    println!("  AN-DNA File Seal Verification");
    println!("════════════════════════════════════════════════════════════");
    kv(4, "Input file", &input.display().to_string());
    kv(4, "Seal sidecar", &seal_path);
    kv(4, "Registry", &registry_path);
    println!("────────────────────────────────────────────────────────────");
    kv(4, "AUTHENTIC", if result.authentic { "yes" } else { "no" });
    kv(4, "UNCHANGED", result.unchanged.as_str());
    if let Some(detail) = &result.unchanged_detail {
        kv(4, "Unchanged detail", detail);
    }
    kv(4, "AUTHORIZED", result.authorized.as_str());
    kv(
        4,
        "RESULT",
        if result.overall_accept {
            "ACCEPT"
        } else {
            "REJECT"
        },
    );
    println!("────────────────────────────────────────────────────────────");
    kv(4, "Summary", &result.summary());
    kv(4, "File hash", &result.computed_file_hash_hex);
    if let Some(h) = &result.computed_manifest_hash_hex {
        kv(4, "Manifest hash", h);
    }
    if let Some(h) = &result.frame_ctx_hash_hex {
        kv(4, "Frame ctx_hash", h);
    }
    println!();

    if let Some(out_path) = evidence_out {
        if let Err(e) = fs::write(&out_path, result.to_json_pretty()) {
            eprintln!("error: cannot write evidence {}: {}", out_path, e);
            return 2;
        }
        println!("Evidence written: {}", out_path);
    }

    if result.overall_accept {
        0
    } else {
        1
    }
}

fn cmd_verify_frame_legacy(args: &[String]) -> i32 {
    if args.is_empty() {
        usage();
    }

    let frame_bytes = if args[0] == "--file" {
        if args.len() < 2 {
            usage();
        }
        match fs::read(&args[1]) {
            Ok(b) => b,
            Err(e) => {
                eprintln!("error: cannot read {}: {}", args[1], e);
                return 2;
            }
        }
    } else {
        hex_decode(&args[0])
    };

    if let Err(e) = ensure_andna_init() {
        eprintln!("error: {}", e);
        return 1;
    }

    let result = unsafe { andna_verify_frame_v2(frame_bytes.as_ptr(), frame_bytes.len()) };
    let msg = strerror(result);

    if result == AndnaErr::Ok {
        println!("PASS: {}", msg);
        0
    } else {
        println!("FAIL ({}): {}", result as i32, msg);
        1
    }
}

fn cmd_smoke() -> i32 {
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
            let msg = strerror(code);
            if !msg.contains(substr) {
                println!(
                    "  [FAIL] strerror({:?}) = {:?}, expected substring {:?}",
                    code, msg, substr
                );
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

    // FIPS Approved Mode entry before crypto-facing smoke tests
    if let Err(e) = ensure_andna_init() {
        println!("  [FAIL] andna_init: {}", e);
        fail += 1;

        println!("\n=== Results: {} passed, {} failed ===", pass, fail);
        return 1;
    } else {
        println!("  [PASS] andna_init: Approved Mode entered");
        pass += 1;
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

    // Test 5: generate + verify if available
    {
        let mut frame = vec![0u8; FRAME_V2_LEN];
        let rc = unsafe { andna_gen_test_frame(frame.as_mut_ptr(), frame.len()) };
        if rc == AndnaErr::Ok {
            let vrc = unsafe { andna_verify_frame_v2(frame.as_ptr(), frame.len()) };
            if vrc == AndnaErr::Ok {
                println!("  [PASS] generated frame → Ok (real ML-DSA-44 backend)");
                pass += 1;
            } else {
                println!("  [FAIL] generated frame verify → {:?}", vrc);
                fail += 1;
            }
        } else {
            println!(
                "  [WARN] gen_test_frame unavailable in current backend: {}",
                strerror(rc)
            );
            println!("         smoke remains valid, but end-user gen requires oqs-backend");
            pass += 1;
        }
    }

    println!("\n=== Results: {} passed, {} failed ===", pass, fail);
    if fail > 0 {
        1
    } else {
        0
    }
}

impl ReplayFile {
    fn new() -> Self {
        Self {
            schema_version: EVIDENCE_SCHEMA_VERSION.to_string(),
            contract_version: CONTRACT_VERSION.to_string(),
            record_count: 0,
            records: Vec::new(),
        }
    }
}

fn load_log(path: &Path) -> io::Result<ReplayFile> {
    if !path.exists() {
        return Ok(ReplayFile::new());
    }
    let raw = fs::read_to_string(path)?;
    serde_json::from_str(&raw).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

fn save_log(path: &Path, replay: &ReplayFile) -> io::Result<()> {
    fs::write(path, to_pretty_json(replay))
}

fn to_pretty_json<T: Serialize>(value: &T) -> String {
    serde_json::to_string_pretty(value).expect("json serialization should not fail")
}

fn strerror(err: AndnaErr) -> String {
    let ptr = andna_strerror(err);
    unsafe { CStr::from_ptr(ptr) }
        .to_string_lossy()
        .into_owned()
}

fn random_array<const N: usize>() -> Result<[u8; N], String> {
    let mut out = [0u8; N];
    getrandom::getrandom(&mut out).map_err(|e| e.to_string())?;
    Ok(out)
}

fn compute_verification_digest(records: &[VerificationRecord]) -> String {
    let mut hasher = Sha3_256::new();
    for r in records {
        let entry = format!(
            "{}|{}|{}|{}|{}\n",
            r.frame_hash, r.frame_len, r.decision, r.error_code, r.contract_version
        );
        hasher.update(entry.as_bytes());
    }
    hex_lower(&hasher.finalize())
}

fn opt_value(args: &[String], flag: &str) -> Option<String> {
    args.windows(2).find_map(|w| {
        if w[0] == flag {
            Some(w[1].clone())
        } else {
            None
        }
    })
}

fn parse_hex_array<const N: usize>(s: &str, label: &str) -> Result<[u8; N], String> {
    let raw = hex::decode(s).map_err(|e| format!("{} is not valid hex: {}", label, e))?;
    if raw.len() != N {
        return Err(format!(
            "{} must be {} bytes / {} hex chars, got {} bytes / {} hex chars",
            label,
            N,
            N * 2,
            raw.len(),
            s.len()
        ));
    }

    let mut out = [0u8; N];
    out.copy_from_slice(&raw);
    Ok(out)
}

fn write_registry_for_bundle(bundle: &SealedBundle, path: &Path) -> io::Result<()> {
    let frame = hex::decode(&bundle.frame_hex)
        .expect("freshly sealed bundle always carries valid frame hex");

    let facts = andna_pipeline::verified_facts_from_accepted_frame(&frame)
        .expect("freshly sealed frame should yield verified facts");

    let registry = CliRegistryFile {
        snapshot_seq: 1,
        as_of_unix_ms: now_unix_ms(),
        policy_version: "andna-seal-cli-registry-v0".to_string(),
        entries: vec![CliRegistryEntry {
            device_id16_hex: hex::encode(facts.device_id16),
            device_id32_hex: hex::encode(facts.device_id32),
            authorized_te_hashes_hex: vec![hex::encode(facts.te_hash)],
            current_epoch: facts.epoch,
            revoked: false,
            frozen: false,
            recovery_hold: false,
            policy_version: "andna-seal-cli-device-v0".to_string(),
        }],
    };

    fs::write(
        path,
        serde_json::to_string_pretty(&registry).expect("CLI registry DTO is always serializable"),
    )
}

fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn print_verify_result(
    path: &Path,
    frame_hash: &str,
    record: &VerificationRecord,
    duration_ms: f64,
) {
    println!("\n════════════════════════════════════════════════════════════");
    println!("  AN-DNA Verification Result");
    println!("════════════════════════════════════════════════════════════");
    kv(4, "Input", &path.display().to_string());
    kv(4, "Frame size", &format!("{} bytes", record.frame_len));
    kv(4, "Frame digest", frame_hash);
    println!("────────────────────────────────────────────────────────────");
    if record.decision == "ACCEPT" {
        kv(4, "Decision", "✓ ACCEPT");
    } else {
        kv(4, "Decision", "✗ REJECT");
        kv(4, "Error code", &record.error_code.to_string());
        kv(4, "Error", record.error_msg.as_deref().unwrap_or("unknown"));
    }
    println!("────────────────────────────────────────────────────────────");
    kv(4, "Engine", &record.engine);
    kv(4, "Contract version", &record.contract_version);
    kv(4, "Duration", &format!("{:.2} ms", duration_ms));
    kv(4, "Run ID", &record.run_id);
    kv(4, "Log", LOG_PATH);
    println!();
}

fn print_replay_header(log_path: &Path, replay: &ReplayFile) {
    println!("\n════════════════════════════════════════════════════════════");
    println!("  AN-DNA Deterministic Replay");
    println!("════════════════════════════════════════════════════════════");
    kv(4, "Log file", &log_path.display().to_string());
    kv(4, "Record count", &replay.records.len().to_string());
    kv(4, "Schema version", &replay.schema_version);
    kv(4, "Contract version", &replay.contract_version);
}

fn print_export_result(output_dir: &Path, manifest: &EvidenceManifest) {
    println!("\n════════════════════════════════════════════════════════════");
    println!("  AN-DNA Evidence Bundle (Rust authoritative path)");
    println!("════════════════════════════════════════════════════════════");
    kv(4, "Output directory", &output_dir.display().to_string());
    kv(4, "Records", &manifest.record_count.to_string());
    println!("\n  Bundle contents:");
    println!(
        "    evidence.json                 {} bytes",
        file_len(&output_dir.join("evidence.json"))
    );
    println!(
        "    manifest.json                 {} bytes",
        file_len(&output_dir.join("manifest.json"))
    );
    if output_dir.join("andna_audit.jsonl").exists() {
        println!(
            "    andna_audit.jsonl             {} bytes",
            file_len(&output_dir.join("andna_audit.jsonl"))
        );
        println!(
            "    audit_validate.json           {} bytes",
            file_len(&output_dir.join("audit_validate.json"))
        );
    }
    println!("────────────────────────────────────────────────────────────");
    kv(4, "Evidence digest", &manifest.evidence_digest);
    kv(4, "Digest algorithm", &manifest.digest_algorithm);
    kv(4, "Contract version", &manifest.contract_version);
    kv(4, "Generated at", &manifest.generated_at);
    println!("────────────────────────────────────────────────────────────\n");
    println!("  ┌─────────────────────────────────────────────────────┐");
    println!("  │  VERIFICATION DIGEST (compare across machines):     │");
    println!("  │  {}  │", manifest.verification_digest);
    println!("  └─────────────────────────────────────────────────────┘\n");
    println!("  This digest covers ONLY deterministic fields:");
    println!("  frame_hash + frame_len + decision + error_code + contract_version");
    println!("  It excludes timestamps, run_ids, and engine names.");
    println!("  If two machines produce the same digest, determinism holds.\n");
}

fn file_len(path: &Path) -> usize {
    fs::metadata(path).map(|m| m.len() as usize).unwrap_or(0)
}

fn kv(indent: usize, label: &str, value: &str) {
    println!(
        "{:indent$}{:<22} {}",
        "",
        format!("{}:", label),
        value,
        indent = indent
    );
}

fn now_nanos() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0)
}

fn now_timestamp() -> String {
    let d = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    format!("{}.{:03}Z", d.as_secs(), d.subsec_millis())
}

fn sha3_256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha3_256::new();
    hasher.update(bytes);
    hex_lower(&hasher.finalize())
}

fn hex_lower(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        use std::fmt::Write as _;
        let _ = write!(&mut out, "{:02x}", b);
    }
    out
}

fn hex_decode(s: &str) -> Vec<u8> {
    let s = s.trim();
    if !s.len().is_multiple_of(2) {
        eprintln!("error: hex string has odd length");
        process::exit(2);
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    let bytes = s.as_bytes();
    for i in (0..bytes.len()).step_by(2) {
        let hi = from_hex(bytes[i]);
        let lo = from_hex(bytes[i + 1]);
        out.push((hi << 4) | lo);
    }
    out
}

fn from_hex(b: u8) -> u8 {
    match b {
        b'0'..=b'9' => b - b'0',
        b'a'..=b'f' => 10 + (b - b'a'),
        b'A'..=b'F' => 10 + (b - b'A'),
        _ => {
            eprintln!("error: invalid hex digit {}", b as char);
            process::exit(2);
        }
    }
}
