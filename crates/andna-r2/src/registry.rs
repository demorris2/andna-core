use crate::lp;
use andna_contracts::{MU_PRE_DEVICE_ID32_LEN, PK_HASH_LEN, TE_DEVICE_ID16_LEN};
use serde::Deserialize;
use sha3::{Digest, Sha3_256};
use std::collections::HashSet;

const R2_REGISTRY_SNAPSHOT_DOMAIN: &[u8] = b"ANDNA-R2-REGISTRY-SNAPSHOT-v0";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Registry {
    pub snapshot_seq: u64,
    pub as_of_unix_ms: u64,
    pub policy_version: String,
    pub entries: Vec<RegistryEntry>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RegistryEntry {
    pub device_id16: [u8; TE_DEVICE_ID16_LEN],
    pub device_id32: [u8; MU_PRE_DEVICE_ID32_LEN],
    pub authorized_te_hashes: Vec<[u8; PK_HASH_LEN]>,
    pub current_epoch: u64,
    pub revoked: bool,
    pub frozen: bool,
    pub recovery_hold: bool,
    pub policy_version: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SnapshotId {
    pub snapshot_seq: u64,
    pub as_of_unix_ms: u64,
    pub snapshot_hash: [u8; 32],
}

#[derive(Debug, PartialEq, Eq)]
pub enum RegistryError {
    Json(String),
    HexField {
        field: &'static str,
        source: String,
    },
    BadWidth {
        field: &'static str,
        expected: usize,
        got: usize,
    },
    DuplicateDevice {
        device_id32_hex: String,
    },
}

#[derive(Deserialize)]
struct RegistryFile {
    snapshot_seq: u64,
    as_of_unix_ms: u64,
    policy_version: String,
    entries: Vec<RegistryEntryFile>,
}

#[derive(Deserialize)]
struct RegistryEntryFile {
    device_id16_hex: String,
    device_id32_hex: String,
    authorized_te_hashes_hex: Vec<String>,
    current_epoch: u64,

    #[serde(default)]
    revoked: bool,

    #[serde(default)]
    frozen: bool,

    #[serde(default)]
    recovery_hold: bool,

    policy_version: String,
}

impl Registry {
    pub fn from_json(s: &str) -> Result<Self, RegistryError> {
        let file: RegistryFile =
            serde_json::from_str(s).map_err(|e| RegistryError::Json(e.to_string()))?;

        let mut entries = Vec::with_capacity(file.entries.len());
        let mut seen = HashSet::new();

        for raw in file.entries {
            let device_id16 =
                decode_fixed::<TE_DEVICE_ID16_LEN>("device_id16_hex", &raw.device_id16_hex)?;

            let device_id32 =
                decode_fixed::<MU_PRE_DEVICE_ID32_LEN>("device_id32_hex", &raw.device_id32_hex)?;

            if !seen.insert(device_id32) {
                return Err(RegistryError::DuplicateDevice {
                    device_id32_hex: hex::encode(device_id32),
                });
            }

            let mut authorized_te_hashes = Vec::with_capacity(raw.authorized_te_hashes_hex.len());
            for h in raw.authorized_te_hashes_hex.iter() {
                authorized_te_hashes
                    .push(decode_fixed::<PK_HASH_LEN>("authorized_te_hashes_hex", h)?);
            }

            entries.push(RegistryEntry {
                device_id16,
                device_id32,
                authorized_te_hashes,
                current_epoch: raw.current_epoch,
                revoked: raw.revoked,
                frozen: raw.frozen,
                recovery_hold: raw.recovery_hold,
                policy_version: raw.policy_version,
            });
        }

        Ok(Self {
            snapshot_seq: file.snapshot_seq,
            as_of_unix_ms: file.as_of_unix_ms,
            policy_version: file.policy_version,
            entries,
        })
    }

    pub fn lookup_by_device_id32(
        &self,
        device_id32: &[u8; MU_PRE_DEVICE_ID32_LEN],
    ) -> Option<&RegistryEntry> {
        self.entries.iter().find(|e| &e.device_id32 == device_id32)
    }

    pub fn snapshot_id(&self) -> SnapshotId {
        SnapshotId {
            snapshot_seq: self.snapshot_seq,
            as_of_unix_ms: self.as_of_unix_ms,
            snapshot_hash: self.snapshot_hash(),
        }
    }

    pub fn snapshot_hash(&self) -> [u8; 32] {
        let canonical = self.canonical_bytes();
        let digest = Sha3_256::digest(&canonical);
        let mut out = [0u8; 32];
        out.copy_from_slice(digest.as_slice());
        out
    }

    fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();

        out.extend_from_slice(R2_REGISTRY_SNAPSHOT_DOMAIN);
        out.extend_from_slice(&self.snapshot_seq.to_le_bytes());
        out.extend_from_slice(&self.as_of_unix_ms.to_le_bytes());
        lp(&mut out, self.policy_version.as_bytes());

        let mut entries = self.entries.clone();
        entries.sort_by(|a, b| a.device_id32.cmp(&b.device_id32));

        let entry_count: u32 = entries
            .len()
            .try_into()
            .expect("too many R2 registry entries");
        out.extend_from_slice(&entry_count.to_le_bytes());

        for e in entries.iter_mut() {
            lp(&mut out, &e.device_id16);
            lp(&mut out, &e.device_id32);

            out.extend_from_slice(&e.current_epoch.to_le_bytes());
            out.push(e.revoked as u8);
            out.push(e.frozen as u8);
            out.push(e.recovery_hold as u8);
            lp(&mut out, e.policy_version.as_bytes());

            e.authorized_te_hashes.sort();

            let auth_count: u32 = e
                .authorized_te_hashes
                .len()
                .try_into()
                .expect("too many authorized T_E hashes");
            out.extend_from_slice(&auth_count.to_le_bytes());

            for h in e.authorized_te_hashes.iter() {
                lp(&mut out, h);
            }
        }

        out
    }
}

fn decode_fixed<const N: usize>(field: &'static str, s: &str) -> Result<[u8; N], RegistryError> {
    let bytes = hex::decode(s).map_err(|e| RegistryError::HexField {
        field,
        source: e.to_string(),
    })?;

    if bytes.len() != N {
        return Err(RegistryError::BadWidth {
            field,
            expected: N,
            got: bytes.len(),
        });
    }

    let mut out = [0u8; N];
    out.copy_from_slice(&bytes);
    Ok(out)
}
