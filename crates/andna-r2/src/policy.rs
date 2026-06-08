use crate::facts::{Stage1Outcome, VerifiedFacts};
use crate::lp;
use crate::registry::{Registry, RegistryEntry};
use andna_contracts::{MU_PRE_DEVICE_ID32_LEN, PK_HASH_LEN, TE_DEVICE_ID16_LEN};
use serde::Serialize;
use sha3::{Digest, Sha3_256};

const R2_POLICY_DIGEST_DOMAIN: &[u8] = b"ANDNA-R2-POLICY-DIGEST-v0";
const ATTESTATION_STATUS_SOFTWARE: &str = "NONE_SOFTWARE_PROFILE";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Stage2Status {
    Authorized,
    NotAuthorized,
    NotEvaluated,
}

impl Stage2Status {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Authorized => "AUTHORIZED",
            Self::NotAuthorized => "NOT_AUTHORIZED",
            Self::NotEvaluated => "NOT_EVALUATED",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reason {
    RegistryEntryValid,
    Stage1Reject,
    NoRegistryEntry,
    DeviceId16Mismatch,
    DeviceRevoked,
    LineageFrozen,
    RecoveryHold,
    EpochStale,
    TeNotAuthorized,
}

impl Reason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::RegistryEntryValid => "registry_entry_valid",
            Self::Stage1Reject => "stage1_reject",
            Self::NoRegistryEntry => "no_registry_entry",
            Self::DeviceId16Mismatch => "device_id16_mismatch",
            Self::DeviceRevoked => "device_revoked",
            Self::LineageFrozen => "lineage_frozen",
            Self::RecoveryHold => "recovery_hold",
            Self::EpochStale => "epoch_stale",
            Self::TeNotAuthorized => "te_not_authorized",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Stage2Decision {
    pub stage1: String,
    pub stage2: String,
    pub reason: String,

    pub attestation_status: String,

    pub device_id16_hex: String,
    pub device_id32_hex: String,
    pub epoch: u64,
    pub te_hash_hex: String,

    pub registry_policy_version: String,
    pub entry_policy_version: Option<String>,
    pub snapshot_seq: u64,
    pub as_of_unix_ms: u64,
    pub snapshot_hash_hex: String,

    /// Present only when Stage 2 evaluated policy.
    ///
    /// For CRYPTO_REJECT, R2 returns NOT_EVALUATED and does not emit a policy
    /// digest over nonexistent authorization facts.
    pub policy_digest_hex: Option<String>,
}

pub fn authorize(stage1: &Stage1Outcome, registry: &Registry) -> Stage2Decision {
    let snapshot_hash = registry.snapshot_hash();

    match stage1 {
        Stage1Outcome::CryptoReject => Stage2Decision {
            stage1: "CRYPTO_REJECT".to_string(),
            stage2: Stage2Status::NotEvaluated.as_str().to_string(),
            reason: Reason::Stage1Reject.as_str().to_string(),
            attestation_status: ATTESTATION_STATUS_SOFTWARE.to_string(),

            device_id16_hex: "00".repeat(TE_DEVICE_ID16_LEN),
            device_id32_hex: "00".repeat(MU_PRE_DEVICE_ID32_LEN),
            epoch: 0,
            te_hash_hex: "00".repeat(PK_HASH_LEN),

            registry_policy_version: registry.policy_version.clone(),
            entry_policy_version: None,
            snapshot_seq: registry.snapshot_seq,
            as_of_unix_ms: registry.as_of_unix_ms,
            snapshot_hash_hex: hex::encode(snapshot_hash),
            policy_digest_hex: None,
        },

        Stage1Outcome::CryptoAccept(facts) => {
            let Some(entry) = registry.lookup_by_device_id32(&facts.device_id32) else {
                return evaluated(
                    facts,
                    registry,
                    None,
                    Stage2Status::NotAuthorized,
                    Reason::NoRegistryEntry,
                    snapshot_hash,
                );
            };

            if entry.device_id16 != facts.device_id16 {
                return evaluated(
                    facts,
                    registry,
                    Some(entry),
                    Stage2Status::NotAuthorized,
                    Reason::DeviceId16Mismatch,
                    snapshot_hash,
                );
            }

            if entry.revoked {
                return evaluated(
                    facts,
                    registry,
                    Some(entry),
                    Stage2Status::NotAuthorized,
                    Reason::DeviceRevoked,
                    snapshot_hash,
                );
            }

            if entry.frozen {
                return evaluated(
                    facts,
                    registry,
                    Some(entry),
                    Stage2Status::NotAuthorized,
                    Reason::LineageFrozen,
                    snapshot_hash,
                );
            }

            if entry.recovery_hold {
                return evaluated(
                    facts,
                    registry,
                    Some(entry),
                    Stage2Status::NotAuthorized,
                    Reason::RecoveryHold,
                    snapshot_hash,
                );
            }

            if facts.epoch != entry.current_epoch {
                return evaluated(
                    facts,
                    registry,
                    Some(entry),
                    Stage2Status::NotAuthorized,
                    Reason::EpochStale,
                    snapshot_hash,
                );
            }

            if !entry
                .authorized_te_hashes
                .iter()
                .any(|h| h == &facts.te_hash)
            {
                return evaluated(
                    facts,
                    registry,
                    Some(entry),
                    Stage2Status::NotAuthorized,
                    Reason::TeNotAuthorized,
                    snapshot_hash,
                );
            }

            evaluated(
                facts,
                registry,
                Some(entry),
                Stage2Status::Authorized,
                Reason::RegistryEntryValid,
                snapshot_hash,
            )
        }
    }
}

fn evaluated(
    facts: &VerifiedFacts,
    registry: &Registry,
    entry: Option<&RegistryEntry>,
    status: Stage2Status,
    reason: Reason,
    snapshot_hash: [u8; 32],
) -> Stage2Decision {
    let entry_policy_version = entry.map(|e| e.policy_version.clone());

    let digest = policy_digest(
        facts,
        registry,
        entry_policy_version.as_deref(),
        status,
        reason,
        snapshot_hash,
    );

    Stage2Decision {
        stage1: "CRYPTO_ACCEPT".to_string(),
        stage2: status.as_str().to_string(),
        reason: reason.as_str().to_string(),
        attestation_status: ATTESTATION_STATUS_SOFTWARE.to_string(),

        device_id16_hex: hex::encode(facts.device_id16),
        device_id32_hex: hex::encode(facts.device_id32),
        epoch: facts.epoch,
        te_hash_hex: hex::encode(facts.te_hash),

        registry_policy_version: registry.policy_version.clone(),
        entry_policy_version,
        snapshot_seq: registry.snapshot_seq,
        as_of_unix_ms: registry.as_of_unix_ms,
        snapshot_hash_hex: hex::encode(snapshot_hash),
        policy_digest_hex: Some(hex::encode(digest)),
    }
}

fn policy_digest(
    facts: &VerifiedFacts,
    registry: &Registry,
    entry_policy_version: Option<&str>,
    status: Stage2Status,
    reason: Reason,
    snapshot_hash: [u8; 32],
) -> [u8; 32] {
    let mut p = Vec::new();

    p.extend_from_slice(R2_POLICY_DIGEST_DOMAIN);
    lp(&mut p, &snapshot_hash);

    p.extend_from_slice(&registry.snapshot_seq.to_le_bytes());
    p.extend_from_slice(&registry.as_of_unix_ms.to_le_bytes());
    lp(&mut p, registry.policy_version.as_bytes());
    lp(&mut p, entry_policy_version.unwrap_or("").as_bytes());

    lp(&mut p, b"CRYPTO_ACCEPT");
    lp(&mut p, status.as_str().as_bytes());
    lp(&mut p, reason.as_str().as_bytes());
    lp(&mut p, ATTESTATION_STATUS_SOFTWARE.as_bytes());

    lp(&mut p, &facts.device_id16);
    lp(&mut p, &facts.device_id32);
    p.extend_from_slice(&facts.epoch.to_le_bytes());
    lp(&mut p, &facts.te_hash);

    let digest = Sha3_256::digest(&p);
    let mut out = [0u8; 32];
    out.copy_from_slice(digest.as_slice());
    out
}
