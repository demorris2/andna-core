"""
AN-DNA vNext Phase 1 — FastAPI Verifier Service

Binary-first ingestion (application/octet-stream). No JSON/Base64 decode
overhead in the hot path. The engine handles all directive enforcement.

Routes:
    POST /verify/vnext     — Verify a 4030-byte Frame V2
    GET  /health           — Engine status
    GET  /evidence         — Export verification evidence log

Usage:
    pip install 'andna[server]'
    uvicorn andna.api:app --host 0.0.0.0 --port 8080

    # Or with VERIFY_ENGINE=rust (once libandna_ffi is built):
    VERIFY_ENGINE=rust uvicorn andna.api:app --host 0.0.0.0 --port 8080

    # Test:
    curl -X POST http://localhost:8080/verify/vnext \\
         -H "Content-Type: application/octet-stream" \\
         --data-binary @frame.bin
"""

from __future__ import annotations

import hashlib
import logging
import os
import time
from contextlib import asynccontextmanager
from typing import Optional

from .contracts import FRAME_V2_LEN, AndnaErr
from .engine import VerifyResult, get_engine, reset_engine
from .logging_config import configure_logging
from .replay import ReplayLog

logger = logging.getLogger(__name__)

# ── Module-level state ──

_replay_log = ReplayLog()


def _get_replay_log() -> ReplayLog:
    return _replay_log


# ── Lazy FastAPI import (so andna package works without fastapi installed) ──

try:
    from fastapi import FastAPI, Request, Response
    from fastapi.responses import JSONResponse

    _FASTAPI_AVAILABLE = True
except ImportError:
    _FASTAPI_AVAILABLE = False


def _require_fastapi():
    if not _FASTAPI_AVAILABLE:
        raise ImportError(
            "FastAPI is required for the verifier service. "
            "Install with: pip install 'andna[server]'"
        )


# ── App factory ──


def create_app() -> "FastAPI":
    """Create and configure the FastAPI application."""
    _require_fastapi()

    configure_logging()

    @asynccontextmanager
    async def lifespan(app):
        engine = get_engine()
        logger.info(
            "AN-DNA verifier started",
            extra={"event": "startup", "engine": engine.name},
        )
        yield
        logger.info("AN-DNA verifier shutdown", extra={"event": "shutdown"})

    app = FastAPI(
        title="AN-DNA vNext Verifier",
        version="1.0.0",
        description="Post-quantum verification engine (ML-DSA-44, FIPS 204)",
        lifespan=lifespan,
    )

    # ── Routes ──

    @app.post("/verify/vnext")
    async def verify_vnext(request: Request) -> JSONResponse:
        """Verify an AN-DNA vNext Phase 1 frame.

        Accepts exactly 4030 bytes (application/octet-stream).
        The engine enforces all security directives (A, B, C, D, E).
        """
        t0 = time.monotonic()
        body = await request.body()
        engine = get_engine()

        # Length pre-check (fast reject before engine)
        if len(body) != FRAME_V2_LEN:
            duration_ms = (time.monotonic() - t0) * 1000
            result = VerifyResult(
                ok=False,
                error_code=AndnaErr.ERR_LENGTH,
                error_msg=f"expected {FRAME_V2_LEN} bytes, got {len(body)}",
            )
            record = _replay_log.capture(body, result, engine.name)
            logger.warning(
                "REJECT: frame length mismatch",
                extra={
                    "event": "verify",
                    "decision": "REJECT",
                    "error_code": result.error_code,
                    "frame_len": len(body),
                    "duration_ms": round(duration_ms, 2),
                    "run_id": record.run_id,
                },
            )
            return JSONResponse(
                status_code=400,
                content={
                    "ok": False,
                    "error_code": result.error_code,
                    "error_msg": result.error_msg,
                    "run_id": record.run_id,
                },
            )

        # ── Core verification — engine handles all directives ──
        result = engine.verify_frame_v2(body)
        duration_ms = (time.monotonic() - t0) * 1000

        # Capture for replay
        record = _replay_log.capture(body, result, engine.name)

        if result.ok:
            logger.info(
                "ACCEPT",
                extra={
                    "event": "verify",
                    "decision": "ACCEPT",
                    "engine": engine.name,
                    "frame_hash": record.frame_hash,
                    "duration_ms": round(duration_ms, 2),
                    "run_id": record.run_id,
                },
            )
            return JSONResponse(
                status_code=200,
                content={
                    "ok": True,
                    "engine": engine.name,
                    "run_id": record.run_id,
                },
            )
        else:
            logger.warning(
                f"REJECT: {result.error_msg}",
                extra={
                    "event": "verify",
                    "decision": "REJECT",
                    "error_code": result.error_code,
                    "engine": engine.name,
                    "frame_hash": record.frame_hash,
                    "duration_ms": round(duration_ms, 2),
                    "run_id": record.run_id,
                },
            )
            return JSONResponse(
                status_code=403,
                content={
                    "ok": False,
                    "error_code": result.error_code,
                    "error_msg": result.error_msg,
                    "run_id": record.run_id,
                },
            )

    @app.get("/health")
    async def health() -> JSONResponse:
        """Engine health check."""
        engine = get_engine()
        return JSONResponse(
            status_code=200,
            content={
                "status": "ok",
                "engine": engine.name,
                "verify_engine_env": os.environ.get("VERIFY_ENGINE", "python"),
                "contract_version": "vNext-Phase1-R1",
            },
        )

    @app.get("/evidence")
    async def evidence() -> JSONResponse:
        """Return current evidence log as JSON."""
        from dataclasses import asdict

        log = _get_replay_log()
        return JSONResponse(
            status_code=200,
            content={
                "record_count": len(log.records),
                "records": [asdict(r) for r in log.records],
            },
        )

    return app


# ── Default app instance (for `uvicorn andna.api:app`) ──

if _FASTAPI_AVAILABLE:
    app = create_app()
