use sha3::{Digest, Sha3_256};

pub const MAGIC: [u8; 8] = *b"ANDNALOG";
pub const VERSION: u32 = 1;

// canonical bytes (hashed) = 174 bytes
pub const CANONICAL_SIZE: usize = 174;
// serialized record = canonical bytes + record_hash[32] = 206 bytes
pub const SERIALIZED_SIZE: usize = 206;

// notes_flags bit positions (u32)
pub const FLAG_HAS_FRAME: u32 = 1 << 0;
pub const FLAG_CRYPTO_REAL: u32 = 1 << 1;
pub const FLAG_REPLAY_REJECT: u32 = 1 << 2;
pub const FLAG_EPOCH_ADVANCED: u32 = 1 << 3;
pub const FLAG_RESERVED_MASK: u32 = !((1 << 4) - 1);

#[derive(Clone, Debug)]
pub struct AuditRecord {
    pub magic: [u8; 8],
    pub version: u32,
    pub run_id: u64,
    pub seq: u64,
    pub ts_unix_ms: u64, // non-authoritative (ordering ignores it), but hashed (tamper-evident)
    pub decision: u8,    // 0=REJECT, 1=ACCEPT
    pub engine: u8,      // 0=python, 1=rust
    pub err_code: i32,   // AndnaErr numeric value
    pub notes_flags: u32,

    pub frame_hash: [u8; 32],
    pub contracts_hash: [u8; 32],
    pub lib_version_hash: [u8; 32],
    pub prev_hash: [u8; 32],

    pub record_hash: [u8; 32], // not part of canonical bytes
}

impl AuditRecord {
    pub fn to_canonical_bytes(&self) -> [u8; CANONICAL_SIZE] {
        let mut buf = [0u8; CANONICAL_SIZE];
        let mut off = 0usize;

        // MAGIC[8]
        buf[off..off + 8].copy_from_slice(&self.magic);
        off += 8;
        // VERSION[u32] LE
        buf[off..off + 4].copy_from_slice(&self.version.to_le_bytes());
        off += 4;
        // RUN_ID[u64]
        buf[off..off + 8].copy_from_slice(&self.run_id.to_le_bytes());
        off += 8;
        // SEQ[u64]
        buf[off..off + 8].copy_from_slice(&self.seq.to_le_bytes());
        off += 8;
        // TS_UNIX_MS[u64]
        buf[off..off + 8].copy_from_slice(&self.ts_unix_ms.to_le_bytes());
        off += 8;
        // DECISION[u8]
        buf[off] = self.decision;
        off += 1;
        // ENGINE[u8]
        buf[off] = self.engine;
        off += 1;
        // ERR_CODE[i32]
        buf[off..off + 4].copy_from_slice(&self.err_code.to_le_bytes());
        off += 4;
        // NOTES_FLAGS[u32]
        buf[off..off + 4].copy_from_slice(&self.notes_flags.to_le_bytes());
        off += 4;

        // FRAME_HASH[32]
        buf[off..off + 32].copy_from_slice(&self.frame_hash);
        off += 32;
        // CONTRACTS_HASH[32]
        buf[off..off + 32].copy_from_slice(&self.contracts_hash);
        off += 32;
        // LIB_VERSION_HASH[32]
        buf[off..off + 32].copy_from_slice(&self.lib_version_hash);
        off += 32;
        // PREV_HASH[32]
        buf[off..off + 32].copy_from_slice(&self.prev_hash);
        off += 32;

        debug_assert_eq!(off, CANONICAL_SIZE);
        buf
    }

    pub fn compute_record_hash(&self) -> [u8; 32] {
        let mut hasher = Sha3_256::new();
        hasher.update(self.to_canonical_bytes());
        hasher.finalize().into()
    }
}

// small helpers
pub fn sha3_256(bytes: &[u8]) -> [u8; 32] {
    let mut h = Sha3_256::new();
    h.update(bytes);
    h.finalize().into()
}

pub fn sha3_256_str(s: &str) -> [u8; 32] {
    sha3_256(s.as_bytes())
}

pub fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

pub fn hex_to_32(s: &str) -> Result<[u8; 32], ()> {
    fn val(c: u8) -> Option<u8> {
        match c {
            b'0'..=b'9' => Some(c - b'0'),
            b'a'..=b'f' => Some(c - b'a' + 10),
            b'A'..=b'F' => Some(c - b'A' + 10),
            _ => None,
        }
    }
    let b = s.as_bytes();
    if b.len() != 64 {
        return Err(());
    }
    let mut out = [0u8; 32];
    for i in 0..32 {
        let hi = val(b[2 * i]).ok_or(())?;
        let lo = val(b[2 * i + 1]).ok_or(())?;
        out[i] = (hi << 4) | lo;
    }
    Ok(out)
}
