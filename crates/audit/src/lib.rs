pub mod canonical;
pub mod export_jsonl;
pub mod sink;
pub mod validator;

pub use canonical::{AuditRecord, MAGIC, VERSION, CANONICAL_SIZE, SERIALIZED_SIZE};
pub use sink::{AuditSink, VerifyEventInput, global_sink, init_sink_if_needed};
pub use validator::{validate_records, validate_jsonl, ValidationError};