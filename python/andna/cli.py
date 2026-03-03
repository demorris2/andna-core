"""
AN-DNA vNext — Deterministic Replay CLI

This is the credibility tool. It proves:
  1. Same frame → same decision, anywhere.
  2. Tampered frame → deterministic rejection with reason code.
  3. Evidence bundle is reproducible and auditable.

Commands:
    andna verify   <frame.bin>              Verify a frame, emit structured result
    andna replay   <verification_log.json>  Replay decisions, prove determinism
    andna export   <output_dir>             Export evidence bundle from session
    andna gen      <output.bin>             Generate a valid sample frame for testing
    andna tamper   <input.bin> <output.bin> Tamper one byte to produce a failing frame

5-Minute Demo Script (Month-4 gate):
    andna gen sample_frame.bin
    andna verify sample_frame.bin
    andna tamper sample_frame.bin tampered_frame.bin
    andna verify tampered_frame.bin
    andna replay verification_log.json
    andna export evidence/

Usage:
    python -m andna verify frame.bin
    python -m andna replay verification_log.json
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
import time
from pathlib import Path
from typing import Optional

from .contracts import (
    FRAME_V2_LEN, MU_PRE_LEN, TE_LEN, SIG_LEN, AndnaErr,
    TE_DEVICE_ID16_OFF, TE_DEVICE_ID16_LEN,
)
from .engine import get_engine, VerifyResult
from .frame_packer import build_mu_pre, pack_frame_v2, device_id32_from_id16
from .replay import ReplayLog, VerificationRecord, CONTRACT_VERSION, EVIDENCE_SCHEMA_VERSION


# ── Session state ──

_session_log = ReplayLog()
_session_log_path: Optional[Path] = None


def _get_session_log_path() -> Path:
    """Default session log: verification_log.json in cwd."""
    global _session_log_path
    if _session_log_path is None:
        _session_log_path = Path("verification_log.json")
    return _session_log_path


def _load_or_create_session_log() -> ReplayLog:
    """Load existing session log or create a new one. Idempotent in-process."""
    global _session_log
    if _session_log.records:
        return _session_log  # Already loaded this process
    path = _get_session_log_path()
    if path.exists():
        try:
            data = json.loads(path.read_text())
            for r in data.get("records", []):
                _session_log.records.append(VerificationRecord(**r))
        except Exception:
            pass  # Start fresh if corrupt
    return _session_log


def _save_session_log() -> None:
    """Persist session log to disk."""
    path = _get_session_log_path()
    _session_log.export_json(path)


# ── Output helpers ──


def _print_result(label: str, value: str, indent: int = 2) -> None:
    """Print a key-value pair with consistent alignment."""
    print(f"{'  ' * indent}{label + ':':<22} {value}")


def _print_header(title: str) -> None:
    print(f"\n{'═' * 60}")
    print(f"  {title}")
    print(f"{'═' * 60}")


def _print_separator() -> None:
    print(f"{'─' * 60}")


# ── Commands ──


def cmd_verify(frame_path: str) -> int:
    """Verify a binary frame file. Returns 0 on ACCEPT, 1 on REJECT."""
    path = Path(frame_path)
    if not path.exists():
        print(f"Error: file not found: {path}", file=sys.stderr)
        return 2

    frame = path.read_bytes()
    engine = get_engine()

    t0 = time.monotonic()
    result = engine.verify_frame_v2(frame)
    duration_ms = (time.monotonic() - t0) * 1000

    # Capture to session log
    _load_or_create_session_log()
    record = _session_log.capture(frame, result, engine.name)
    _save_session_log()

    # Display
    frame_hash = hashlib.sha256(frame).hexdigest()

    _print_header("AN-DNA Verification Result")
    _print_result("Input", str(path))
    _print_result("Frame size", f"{len(frame)} bytes")
    _print_result("Frame SHA-256", frame_hash)
    _print_separator()

    if result.ok:
        _print_result("Decision", "✓ ACCEPT")
    else:
        _print_result("Decision", "✗ REJECT")
        _print_result("Error code", str(result.error_code))
        _print_result("Error", result.error_msg or "unknown")

    _print_separator()
    _print_result("Engine", engine.name)
    _print_result("Contract version", CONTRACT_VERSION)
    _print_result("Duration", f"{duration_ms:.2f} ms")
    _print_result("Run ID", record.run_id)
    _print_result("Log", str(_get_session_log_path()))
    print()

    return 0 if result.ok else 1


def cmd_replay(log_path: str, frame_path: Optional[str] = None) -> int:
    """Replay a verification log. Proves decisions are deterministic.

    If --frame is provided, re-verify the frame and assert the decision
    and frame_hash match the first record in the log.
    """
    path = Path(log_path)
    if not path.exists():
        print(f"Error: file not found: {path}", file=sys.stderr)
        return 2

    data = json.loads(path.read_text())
    records = data.get("records", [])

    if not records:
        print("Error: no records in log file", file=sys.stderr)
        return 2

    _print_header("AN-DNA Deterministic Replay")
    _print_result("Log file", str(path))
    _print_result("Record count", str(len(records)))
    _print_result("Schema version", data.get("schema_version", "unknown"))
    _print_result("Contract version", data.get("contract_version", "unknown"))

    # ── Frame re-verification mode ──
    if frame_path:
        fp = Path(frame_path)
        if not fp.exists():
            print(f"Error: frame file not found: {fp}", file=sys.stderr)
            return 2

        frame = fp.read_bytes()
        frame_hash = hashlib.sha256(frame).hexdigest()

        # Find matching record by frame_hash
        matching = [r for r in records if r.get("frame_hash") == frame_hash]
        if not matching:
            _print_separator()
            print(f"\n  ✗ No record matches frame hash {frame_hash[:16]}...")
            print(f"    Frame may not be from this verification session.\n")
            return 1

        rec = matching[0]
        _print_separator()
        print(f"\n  Re-verifying frame: {fp}")
        _print_result("Frame SHA-256", frame_hash, indent=3)
        _print_result("Recorded decision", rec["decision"], indent=3)

        # Re-verify
        engine = get_engine()
        result = engine.verify_frame_v2(frame)
        new_decision = "ACCEPT" if result.ok else "REJECT"

        _print_result("Re-verify decision", new_decision, indent=3)
        _print_result("Re-verify engine", engine.name, indent=3)

        if new_decision == rec["decision"]:
            print(f"\n      ✓ Deterministic: same frame → same decision")
            print(f"        Recorded: {rec['decision']}  |  Re-verified: {new_decision}\n")
            return 0
        else:
            print(f"\n      ✗ NON-DETERMINISTIC: decisions differ!")
            print(f"        Recorded: {rec['decision']}  |  Re-verified: {new_decision}\n")
            return 1

    # ── Standard structural replay ──
    _print_separator()

    all_valid = True
    for i, rec in enumerate(records):
        run_id = rec.get("run_id", "?")
        decision = rec.get("decision", "?")
        frame_hash = rec.get("frame_hash", "?")
        error_code = rec.get("error_code", 0)
        engine = rec.get("engine", "?")
        contract = rec.get("contract_version", "?")

        print(f"\n  Record {i + 1}/{len(records)}")
        _print_result("Run ID", run_id, indent=3)
        _print_result("Decision", decision, indent=3)
        _print_result("Frame hash", frame_hash, indent=3)
        _print_result("Error code", str(error_code), indent=3)
        _print_result("Engine", engine, indent=3)
        _print_result("Contract", contract, indent=3)

        # Verify structural integrity
        if not frame_hash or len(frame_hash) != 64:
            print(f"      ⚠  Frame hash missing or malformed")
            all_valid = False
        elif not run_id.startswith("run-"):
            print(f"      ⚠  Run ID format invalid")
            all_valid = False
        else:
            print(f"      ✓  Record structure valid")

    _print_separator()

    if all_valid:
        print(f"\n  ✓ Replay verified: {len(records)} record(s), all structurally valid.")
        print(f"  Determinism claim: same frame → same hash → same decision.")
        print(f"  To fully verify: `andna replay <log> --frame <frame.bin>`\n")
        return 0
    else:
        print(f"\n  ✗ Replay has structural issues. See warnings above.\n")
        return 1


def cmd_export(output_dir: str) -> int:
    """Export evidence bundle from current session log."""
    _load_or_create_session_log()

    if not _session_log.records:
        print("Error: no verification records in session.", file=sys.stderr)
        print(f"Run `andna verify <frame.bin>` first.", file=sys.stderr)
        return 2

    output = Path(output_dir)
    bundle_dir = _session_log.export_evidence_bundle(output)

    _print_header("AN-DNA Evidence Bundle")
    _print_result("Output directory", str(bundle_dir))
    _print_result("Records", str(len(_session_log.records)))

    # List bundle contents
    print(f"\n  Bundle contents:")
    for f in sorted(bundle_dir.iterdir()):
        size = f.stat().st_size
        print(f"    {f.name:<24} {size:>8,} bytes")

    _print_separator()

    # Show manifest
    manifest = json.loads((bundle_dir / "manifest.json").read_text())
    _print_result("Evidence SHA-256", manifest["evidence_sha256"])
    _print_result("Contract version", manifest["contract_version"])
    _print_result("Generated at", manifest["generated_at"])
    _print_separator()

    vd = manifest.get("verification_digest", "N/A")
    print(f"\n  ┌─────────────────────────────────────────────────────┐")
    print(f"  │  VERIFICATION DIGEST (compare across machines):     │")
    print(f"  │  {vd}  │")
    print(f"  └─────────────────────────────────────────────────────┘")
    print(f"\n  This digest covers ONLY deterministic fields:")
    print(f"  frame_hash + decision + error_code + contract_version")
    print(f"  It excludes timestamps, run_ids, and engine names.")
    print(f"  If two machines produce the same digest, determinism holds.\n")

    return 0


def cmd_gen(output_path: str) -> int:
    """Generate a sample frame. Uses Rust signer if available, else dummy."""
    from andna.contracts import FRAME_V2_LEN

    rust_signed = False
    try:
        from andna.native import gen_test_frame
        frame = gen_test_frame()
        rust_signed = True
        expected_decision = "ACCEPT"
    except Exception:
        # Fallback: structural-only frame (Python engine will accept, Rust won't)
        from andna.frame_packer import build_mu_pre, pack_frame_v2
        from andna.contracts import TE_V1_LEN as TE_LEN, SIG_LEN
        te = bytes(TE_LEN)
        from andna.frame_packer import device_id32_from_id16
        valid_id32 = device_id32_from_id16(te[1320:1336])
        mp = build_mu_pre(
            te=te, device_id32=valid_id32, epoch=0,
            sid=b"\x00" * 32, n_d=b"\x00" * 32, n_s=b"\x00" * 32,
            ctx_hash=b"\x00" * 32,
        )
        frame = pack_frame_v2(mu_pre=mp, te=te, sig=bytes(SIG_LEN))
        expected_decision = "ACCEPT (python-only; Rust will reject dummy sig)"

    Path(output_path).write_bytes(frame)

    sha = hashlib.sha256(frame).hexdigest()
    print()
    print("=" * 60)
    print("  AN-DNA Sample Frame Generated")
    print("=" * 60)
    print(f"    Output:                {output_path}")
    print(f"    Size:                  {len(frame)} bytes")
    print(f"    SHA-256:               {sha}")
    print(f"    Signed by:             {'rust/liboqs' if rust_signed else 'dummy (no sig)'}")
    print(f"    Expected decision:     {expected_decision}")
    print()
    return 0


def cmd_tamper(input_path: str, output_path: str) -> int:
    """Read a frame, flip one byte in the pk_hash, write tampered frame."""
    inp = Path(input_path)
    if not inp.exists():
        print(f"Error: file not found: {inp}", file=sys.stderr)
        return 2

    frame = bytearray(inp.read_bytes())

    if len(frame) != FRAME_V2_LEN:
        print(f"Error: expected {FRAME_V2_LEN} bytes, got {len(frame)}", file=sys.stderr)
        return 2

    # Tamper: flip byte 0 (first byte of pk_hash)
    original_byte = frame[0]
    frame[0] ^= 0xFF

    out = Path(output_path)
    out.write_bytes(bytes(frame))

    _print_header("AN-DNA Frame Tampered")
    _print_result("Input", str(inp))
    _print_result("Output", str(out))
    _print_result("Tampered byte", f"offset 0: 0x{original_byte:02X} → 0x{frame[0]:02X}")
    _print_result("Expected decision", "REJECT (pk_hash mismatch)")
    print()

    return 0


# ── CLI entry point ──


USAGE = """\
AN-DNA vNext — Deterministic Replay CLI

Usage:
    python -m andna verify   <frame.bin>               Verify a binary frame
    python -m andna replay   <log.json>                Replay and validate decisions
    python -m andna replay   <log.json> --frame <f.bin> Re-verify frame, assert same decision
    python -m andna export   <output_dir>              Export evidence bundle
    python -m andna gen      <output.bin>              Generate valid sample frame
    python -m andna tamper   <input.bin> <output.bin>   Flip one byte to create a reject

5-Minute Demo:
    python -m andna gen sample_frame.bin
    python -m andna verify sample_frame.bin
    python -m andna tamper sample_frame.bin tampered_frame.bin
    python -m andna verify tampered_frame.bin
    python -m andna replay verification_log.json
    python -m andna replay verification_log.json --frame sample_frame.bin
    python -m andna export evidence/
"""


def main(argv: Optional[list] = None) -> int:
    args = argv if argv is not None else sys.argv[1:]

    if not args or args[0] in ("-h", "--help", "help"):
        print(USAGE)
        return 0

    cmd = args[0]

    if cmd == "verify" and len(args) == 2:
        return cmd_verify(args[1])
    elif cmd == "replay" and len(args) >= 2:
        log_file = args[1]
        frame_file = None
        if "--frame" in args:
            idx = args.index("--frame")
            if idx + 1 < len(args):
                frame_file = args[idx + 1]
            else:
                print("Error: --frame requires a file path", file=sys.stderr)
                return 2
        return cmd_replay(log_file, frame_file)
    elif cmd == "export" and len(args) == 2:
        return cmd_export(args[1])
    elif cmd == "gen" and len(args) == 2:
        return cmd_gen(args[1])
    elif cmd == "tamper" and len(args) == 3:
        return cmd_tamper(args[1], args[2])
    else:
        print(f"Unknown command or wrong arguments: {' '.join(args)}")
        print(USAGE)
        return 2


if __name__ == "__main__":
    sys.exit(main())
