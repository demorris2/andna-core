use std::sync::{Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::canonical::{
    sha3_256, sha3_256_str, AuditRecord, FLAG_CRYPTO_REAL, FLAG_HAS_FRAME, FLAG_RESERVED_MASK,
    MAGIC, VERSION,
};

#[derive(Clone, Debug)]
pub struct VerifyEventInput<'a> {
    pub ts_unix_ms: u64,
    pub decision: u8, // 0/1
    pub engine: u8,   // 0 python, 1 rust
    pub err_code: i32,
    pub notes_flags: u32,
    pub frame_bytes: Option<&'a [u8]>, // if None => HAS_FRAME must be 0 and frame_hash zeros
    pub frame_hash: Option<[u8; 32]>,  // Direct hash injection bypasses hashing bytes
}

pub struct AuditSink {
    pub run_id: u64,
    next_seq: u64,
    last_hash: [u8; 32],
    records: Vec<AuditRecord>,
    contracts_hash: [u8; 32],
    lib_version_hash: [u8; 32],
}

impl AuditSink {
    pub fn new(lib_version_str: &str) -> Self {
        let run_id = make_run_id();
        let contracts_hash = contracts_header_hash();
        let lib_version_hash = sha3_256_str(lib_version_str);

        Self {
            run_id,
            next_seq: 0,
            last_hash: [0u8; 32],
            records: Vec::new(),
            contracts_hash,
            lib_version_hash,
        }
    }

    pub fn reset_run(&mut self, lib_version_str: &str) {
        *self = Self::new(lib_version_str);
    }

    pub fn append_verify(&mut self, mut inp: VerifyEventInput<'_>) -> AuditRecord {
        // Enforce reserved bits = 0
        if (inp.notes_flags & FLAG_RESERVED_MASK) != 0 {
            inp.notes_flags &= !FLAG_RESERVED_MASK;
        }

        // Enforce CRYPTO_REAL based on build feature
        let crypto_real = cfg!(feature = "oqs-backend");
        if crypto_real {
            inp.notes_flags |= FLAG_CRYPTO_REAL;
        } else {
            inp.notes_flags &= !FLAG_CRYPTO_REAL;
        }

        // Missing frame rule (deterministic)
        let (has_frame, frame_hash) = match (inp.frame_bytes, inp.frame_hash) {
            (_, Some(hash)) => {
                inp.notes_flags |= FLAG_HAS_FRAME;
                (true, hash)
            }
            (Some(bytes), None) => {
                inp.notes_flags |= FLAG_HAS_FRAME;
                (true, sha3_256(bytes))
            }
            (None, None) => {
                inp.notes_flags &= !FLAG_HAS_FRAME;
                (false, [0u8; 32])
            }
        };

        // If HAS_FRAME=0, frame_hash MUST be zero
        if !has_frame {
            // already enforced above
        }

        let mut rec = AuditRecord {
            magic: MAGIC,
            version: VERSION,
            run_id: self.run_id,
            seq: self.next_seq,
            ts_unix_ms: inp.ts_unix_ms,
            decision: inp.decision,
            engine: inp.engine,
            err_code: inp.err_code,
            notes_flags: inp.notes_flags,

            frame_hash,
            contracts_hash: self.contracts_hash,
            lib_version_hash: self.lib_version_hash,
            prev_hash: self.last_hash,

            record_hash: [0u8; 32],
        };

        rec.record_hash = rec.compute_record_hash();

        // advance sink state
        self.last_hash = rec.record_hash;
        self.next_seq += 1;
        self.records.push(rec.clone());

        rec
    }

    pub fn snapshot(&self) -> Vec<AuditRecord> {
        self.records.clone()
    }
}

fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn make_run_id() -> u64 {
    // uniqueness > determinism; bounded to process/session
    let t = now_unix_ms();
    let pid = std::process::id() as u64;
    (t << 16) ^ (pid << 1) ^ 0xA5A5u64
}

fn contracts_header_hash() -> [u8; 32] {
    // Uses committed generated header as machine-checkable SoT.
    // Path: crates/audit/../../include/andna_vnext_contracts.h
    let bytes = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../include/andna_vnext_contracts.h"
    ));
    sha3_256(bytes)
}

// ── global sink (Rust-owned) ──
static GLOBAL: OnceLock<Mutex<AuditSink>> = OnceLock::new();

pub fn init_sink_if_needed(lib_version_str: &str) -> &'static Mutex<AuditSink> {
    GLOBAL.get_or_init(|| {
        let mut sink = AuditSink::new(lib_version_str);

        // Auto-restore state from Gate 2 log if it exists to maintain the chain across CLI runs
        if let Ok(content) = std::fs::read_to_string("andna_audit.jsonl") {
            if let Ok(records) = crate::validator::parse_jsonl(&content) {
                if let Some(last) = records.last() {
                    sink.run_id = last.run_id;
                    sink.next_seq = last.seq + 1;
                    sink.last_hash = last.record_hash;
                    sink.records = records;
                }
            }
        }

        Mutex::new(sink)
    })
}

pub fn global_sink() -> &'static Mutex<AuditSink> {
    // fallback if caller didn’t initialize explicitly
    init_sink_if_needed(env!("CARGO_PKG_VERSION"))
}

pub fn now_ms() -> u64 {
    now_unix_ms()
}
