pub mod canonical;
pub mod export_jsonl;
pub mod sink;
pub mod validator;

pub use canonical::{AuditRecord, CANONICAL_SIZE, MAGIC, SERIALIZED_SIZE, VERSION};
pub use sink::{global_sink, init_sink_if_needed, AuditSink, VerifyEventInput};
pub use validator::{validate_jsonl, validate_records, ValidationError};

#[cfg(test)]
mod tests;