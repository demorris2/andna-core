"""
AN-DNA vNext — Verification Replay & Evidence Capture

Captures every verification event as a structured record suitable for
audit replay. Records are append-only and include enough information
to reproduce the verification outcome on a clean machine.

Evidence bundle = frame_hash + decision + error_code + contract_version + engine + timestamp

Usage:
    from andna.replay import ReplayLog, VerificationRecord

    log = ReplayLog()
    record = log.capture(frame, result, engine_name)
    log.export_json("verification_log.json")
"""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import List, Optional

from .contracts import FRAME_V2_LEN, MU_PRE_LEN


# Version of the evidence record schema
EVIDENCE_SCHEMA_VERSION = "1.0.0"

# Contract version from R1 freeze
CONTRACT_VERSION = "vNext-Phase1-R1"


@dataclass(frozen=True, slots=True)
class VerificationRecord:
    """A single verification event, sufficient for deterministic replay."""

    # Unique run identifier (timestamp-based)
    run_id: str

    # ISO-8601 UTC timestamp
    timestamp: str

    # SHA-256 of the raw input frame
    frame_hash: str

    # Frame length in bytes
    frame_len: int

    # Verification decision
    decision: str  # "ACCEPT" or "REJECT"

    # Error code (0 = OK)
    error_code: int

    # Error message (None if accepted)
    error_msg: Optional[str]

    # Engine that produced the result
    engine: str

    # Contract version
    contract_version: str = CONTRACT_VERSION

    # Evidence schema version
    schema_version: str = EVIDENCE_SCHEMA_VERSION


@dataclass
class ReplayLog:
    """Append-only log of verification events."""

    records: List[VerificationRecord] = field(default_factory=list)

    def capture(
        self,
        frame: bytes,
        result,  # VerifyResult from engine
        engine_name: str,
    ) -> VerificationRecord:
        """Capture a verification event and append to the log."""
        now = time.time()
        ts = time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(now))
        ts += f".{int((now % 1) * 1000):03d}Z"

        run_id = f"run-{time.time_ns()}"
        frame_hash = hashlib.sha256(frame).hexdigest()

        record = VerificationRecord(
            run_id=run_id,
            timestamp=ts,
            frame_hash=frame_hash,
            frame_len=len(frame),
            decision="ACCEPT" if result.ok else "REJECT",
            error_code=result.error_code,
            error_msg=result.error_msg,
            engine=engine_name,
        )

        self.records.append(record)
        return record

    def export_json(self, path: str | Path) -> Path:
        """Export all records as a JSON file."""
        path = Path(path)
        data = {
            "schema_version": EVIDENCE_SCHEMA_VERSION,
            "contract_version": CONTRACT_VERSION,
            "record_count": len(self.records),
            "records": [asdict(r) for r in self.records],
        }
        path.write_text(json.dumps(data, indent=2))
        return path

    def compute_verification_digest(self) -> str:
        """Compute SHA-256 over only deterministic fields.

        This digest is identical across machines when the same frames
        produce the same decisions. It excludes timestamps, run_ids,
        and engine names — only frame_hash + decision + error_code +
        contract_version are included.

        This is the number you compare across hosts.
        """
        h = hashlib.sha256()
        for r in self.records:
            # Canonical deterministic tuple
            entry = f"{r.frame_hash}|{r.frame_len}|{r.decision}|{r.error_code}|{r.contract_version}\n"
            h.update(entry.encode("utf-8"))
        return h.hexdigest()

    def export_evidence_bundle(self, output_dir: str | Path) -> Path:
        """Export a complete evidence bundle directory.

        Bundle contents:
          evidence.json  — structured verification records
          manifest.json  — bundle metadata (hashes, counts, versions)

        The manifest includes a verification_digest that hashes only
        deterministic fields. This digest MUST match across machines.
        """
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)

        # Write evidence log
        evidence_path = output_dir / "evidence.json"
        self.export_json(evidence_path)

        # Compute integrity hash of evidence file
        evidence_hash = hashlib.sha256(evidence_path.read_bytes()).hexdigest()

        # Compute deterministic verification digest
        verification_digest = self.compute_verification_digest()

        # Write manifest
        manifest = {
            "schema_version": EVIDENCE_SCHEMA_VERSION,
            "contract_version": CONTRACT_VERSION,
            "record_count": len(self.records),
            "evidence_file": "evidence.json",
            "evidence_sha256": evidence_hash,
            "verification_digest": verification_digest,
            "generated_at": time.strftime(
                "%Y-%m-%dT%H:%M:%SZ", time.gmtime()
            ),
        }

        manifest_path = output_dir / "manifest.json"
        manifest_path.write_text(json.dumps(manifest, indent=2))

        return output_dir

    def verify_replay(self, frame: bytes, record: VerificationRecord) -> bool:
        """Verify that replaying a frame produces the same frame_hash."""
        return hashlib.sha256(frame).hexdigest() == record.frame_hash
