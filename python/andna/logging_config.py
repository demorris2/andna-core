"""
AN-DNA vNext — Deterministic Structured Logging

All verification events are logged as single-line JSON objects suitable
for audit replay and evidence capture.

Usage:
    from andna.logging_config import configure_logging
    configure_logging()  # call once at startup
"""

import json
import logging
import sys
import time
from typing import Any, Dict, Optional


class StructuredFormatter(logging.Formatter):
    """Emit each log record as a single-line JSON object.

    Fields:
        ts:       ISO-8601 timestamp (UTC)
        level:    DEBUG / INFO / WARNING / ERROR
        logger:   logger name
        msg:      human-readable message
        **extra:  any extra fields passed via `extra=` kwarg
    """

    def format(self, record: logging.LogRecord) -> str:
        payload: Dict[str, Any] = {
            "ts": time.strftime(
                "%Y-%m-%dT%H:%M:%S", time.gmtime(record.created)
            )
            + f".{int(record.msecs):03d}Z",
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }

        # Merge any extra fields
        for key in ("event", "engine", "error_code", "error_msg",
                     "frame_len", "decision", "duration_ms",
                     "run_id", "frame_hash", "contract_version",
                     "engine_sha"):
            val = getattr(record, key, None)
            if val is not None:
                payload[key] = val

        return json.dumps(payload, separators=(",", ":"))


def configure_logging(level: int = logging.INFO) -> None:
    """Configure root logger with structured JSON output to stderr."""
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(StructuredFormatter())

    root = logging.getLogger()
    root.handlers.clear()
    root.addHandler(handler)
    root.setLevel(level)
