use serde::Deserialize;

use crate::canonical::{
    AuditRecord, MAGIC, VERSION,
    FLAG_HAS_FRAME, FLAG_RESERVED_MASK,
    hex_to_32,
};

#[derive(Debug)]
pub enum ValidationError {
    Empty,
    BadMagic,
    BadVersion,
    RunIdMismatch,
    SeqGap { at_seq: u64 },
    PrevHashMismatch { at_seq: u64 },
    RecordHashMismatch { at_seq: u64 },
    MissingFrameConstraintViolation { at_seq: u64 },
    ReservedBitsSet { at_seq: u64 },
    JsonParse,
    HexDecode,
}

pub fn validate_records(records: &[AuditRecord]) -> Result<(), ValidationError> {
    if records.is_empty() { return Err(ValidationError::Empty); }

    let run_id = records[0].run_id;
    let mut expected_prev = [0u8; 32];

    for (i, r) in records.iter().enumerate() {
        if r.magic != MAGIC { return Err(ValidationError::BadMagic); }
        if r.version != VERSION { return Err(ValidationError::BadVersion); }
        if r.run_id != run_id { return Err(ValidationError::RunIdMismatch); }

        let expected_seq = i as u64;
        if r.seq != expected_seq { return Err(ValidationError::SeqGap { at_seq: r.seq }); }
        if r.prev_hash != expected_prev { return Err(ValidationError::PrevHashMismatch { at_seq: r.seq }); }

        if (r.notes_flags & FLAG_RESERVED_MASK) != 0 {
            return Err(ValidationError::ReservedBitsSet { at_seq: r.seq });
        }

        let has_frame = (r.notes_flags & FLAG_HAS_FRAME) != 0;
        if !has_frame && r.frame_hash != [0u8; 32] {
            return Err(ValidationError::MissingFrameConstraintViolation { at_seq: r.seq });
        }

        let computed = r.compute_record_hash();
        if computed != r.record_hash {
            return Err(ValidationError::RecordHashMismatch { at_seq: r.seq });
        }

        expected_prev = r.record_hash;
    }

    Ok(())
}

#[derive(Deserialize)]
struct JsonRec {
    magic: String,
    version: u32,
    run_id: u64,
    seq: u64,
    ts_unix_ms: u64,
    decision: u8,
    engine: u8,
    err_code: i32,
    notes_flags: u32,
    frame_hash: String,
    contracts_hash: String,
    lib_version_hash: String,
    prev_hash: String,
    record_hash: String,
}

pub fn parse_jsonl(jsonl: &str) -> Result<Vec<AuditRecord>, ValidationError> {
    let mut records: Vec<AuditRecord> = Vec::new();

    for line in jsonl.lines() {
        if line.trim().is_empty() { continue; }
        let jr: JsonRec = serde_json::from_str(line).map_err(|_| ValidationError::JsonParse)?;

        if jr.magic.as_bytes().len() != 8 { return Err(ValidationError::BadMagic); }
        let mut magic = [0u8; 8];
        magic.copy_from_slice(jr.magic.as_bytes());

        let frame_hash = hex_to_32(&jr.frame_hash).map_err(|_| ValidationError::HexDecode)?;
        let contracts_hash = hex_to_32(&jr.contracts_hash).map_err(|_| ValidationError::HexDecode)?;
        let lib_version_hash = hex_to_32(&jr.lib_version_hash).map_err(|_| ValidationError::HexDecode)?;
        let prev_hash = hex_to_32(&jr.prev_hash).map_err(|_| ValidationError::HexDecode)?;
        let record_hash = hex_to_32(&jr.record_hash).map_err(|_| ValidationError::HexDecode)?;

        let rec = AuditRecord {
            magic,
            version: jr.version,
            run_id: jr.run_id,
            seq: jr.seq,
            ts_unix_ms: jr.ts_unix_ms,
            decision: jr.decision,
            engine: jr.engine,
            err_code: jr.err_code,
            notes_flags: jr.notes_flags,
            frame_hash,
            contracts_hash,
            lib_version_hash,
            prev_hash,
            record_hash,
        };

        records.push(rec);
    }

    Ok(records)
}

pub fn validate_jsonl(jsonl: &str) -> Result<(), ValidationError> {
    let records = parse_jsonl(jsonl)?;
    validate_records(&records)
}