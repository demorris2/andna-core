//! The seal manifest: a minimal, deterministic description of a sealed file. Its canonical
//! hash is what gets bound into `mu_pre.ctx_hash`.

use crate::lp;
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};

const MANIFEST_DOMAIN: &[u8] = b"ANDNA-SEAL-MANIFEST-v0";

pub const MANIFEST_SCHEMA_VERSION: &str = "andna-seal-manifest-v0";
pub const DIGEST_ALGORITHM: &str = "sha3-256";
pub const MANIFEST_POLICY_V0: &str = "detached-file-integrity-v0";

/// Length of a SHA3-256 digest.
const DIGEST_LEN: usize = 32;

/// Minimal, deterministic manifest for a sealed file. No timestamp (timestamps would make
/// the manifest hash nondeterministic and complicate golden tests).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Manifest {
    pub schema_version: String,
    pub digest_algorithm: String,
    pub file_name: String,
    pub file_size: u64,
    pub file_hash_hex: String,
    pub manifest_policy: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_type: Option<String>,
}

/// Errors handling seal/manifest/frame encodings.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SealError {
    BadFileHashHex(String),
    FileHashWidth { expected: usize, got: usize },
    UnsupportedDigestAlgorithm(String),
}

impl Manifest {
    /// Build a manifest for raw file bytes using SHA3-256 as the content digest.
    pub fn for_file(
        file_name: impl Into<String>,
        file_bytes: &[u8],
        content_type: Option<String>,
    ) -> Manifest {
        let mut h = Sha3_256::new();
        h.update(file_bytes);
        let digest = h.finalize();
        Manifest {
            schema_version: MANIFEST_SCHEMA_VERSION.to_string(),
            digest_algorithm: DIGEST_ALGORITHM.to_string(),
            file_name: file_name.into(),
            file_size: file_bytes.len() as u64,
            file_hash_hex: hex::encode(digest),
            manifest_policy: MANIFEST_POLICY_V0.to_string(),
            content_type,
        }
    }

    /// Decode the declared file hash to raw bytes (validates algorithm, hex, and width).
    pub fn file_hash(&self) -> Result<[u8; DIGEST_LEN], SealError> {
        if self.digest_algorithm != DIGEST_ALGORITHM {
            return Err(SealError::UnsupportedDigestAlgorithm(
                self.digest_algorithm.clone(),
            ));
        }
        let raw = hex::decode(&self.file_hash_hex)
            .map_err(|e| SealError::BadFileHashHex(e.to_string()))?;
        if raw.len() != DIGEST_LEN {
            return Err(SealError::FileHashWidth {
                expected: DIGEST_LEN,
                got: raw.len(),
            });
        }
        let mut out = [0u8; DIGEST_LEN];
        out.copy_from_slice(&raw);
        Ok(out)
    }

    /// Domain-separated, length-prefixed canonical encoding — NOT JSON. Stable under
    /// serialization/whitespace/field-order differences. Every variable field is
    /// length-prefixed so distinct field contents cannot collide by concatenation.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(MANIFEST_DOMAIN);
        lp(&mut buf, self.schema_version.as_bytes());
        lp(&mut buf, self.digest_algorithm.as_bytes());
        lp(&mut buf, self.file_name.as_bytes());
        buf.extend_from_slice(&self.file_size.to_le_bytes());
        lp(&mut buf, self.file_hash_hex.as_bytes());
        lp(&mut buf, self.manifest_policy.as_bytes());
        lp(
            &mut buf,
            self.content_type.as_deref().unwrap_or("").as_bytes(),
        );
        buf
    }

    /// SHA3-256 over [`Manifest::canonical_bytes`]. This is bound into `mu_pre.ctx_hash`.
    pub fn manifest_hash(&self) -> [u8; DIGEST_LEN] {
        let mut h = Sha3_256::new();
        h.update(self.canonical_bytes());
        let out = h.finalize();
        let mut d = [0u8; DIGEST_LEN];
        d.copy_from_slice(&out);
        d
    }
}
