use crate::canonical::{hex_lower, AuditRecord};

/// Deterministic JSONL export:
/// - one JSON object per line
/// - fixed field order
/// - lowercase hex for hashes
/// - newline at EOF
pub fn to_jsonl(records: &[AuditRecord]) -> String {
    let mut out = String::new();
    for r in records {
        out.push_str(&record_to_line(r));
        out.push('\n');
    }
    out
}

fn record_to_line(r: &AuditRecord) -> String {
    // fixed field order, no nulls
    format!(
        concat!(
          "{{",
          "\"magic\":\"{}\",",
          "\"version\":{},",
          "\"run_id\":{},",
          "\"seq\":{},",
          "\"ts_unix_ms\":{},",
          "\"decision\":{},",
          "\"engine\":{},",
          "\"err_code\":{},",
          "\"notes_flags\":{},",
          "\"frame_hash\":\"{}\",",
          "\"contracts_hash\":\"{}\",",
          "\"lib_version_hash\":\"{}\",",
          "\"prev_hash\":\"{}\",",
          "\"record_hash\":\"{}\"",
          "}}"
        ),
        std::str::from_utf8(&r.magic).unwrap_or("ANDNALOG"),
        r.version,
        r.run_id,
        r.seq,
        r.ts_unix_ms,
        r.decision,
        r.engine,
        r.err_code,
        r.notes_flags,
        hex_lower(&r.frame_hash),
        hex_lower(&r.contracts_hash),
        hex_lower(&r.lib_version_hash),
        hex_lower(&r.prev_hash),
        hex_lower(&r.record_hash),
    )
}