"""
AN-DNA Verifier Service — Minimal Flask Integration Example

This shows the exact 3-line change to wire AN-DNA verification into
an existing Python HTTP service. Switch to Rust: set VERIFY_ENGINE=rust
and ensure libandna_ffi.so is on the library path. No code change.

Usage:
    pip install flask
    VERIFY_ENGINE=python python examples/flask_verifier.py

    # Test:
    curl -X POST http://localhost:8080/verify \
         -H "Content-Type: application/octet-stream" \
         --data-binary @frame.bin
"""
import os
from flask import Flask, request, jsonify

# ── 3-line AN-DNA integration ──
from andna.engine import get_engine
from andna.contracts import FRAME_V2_LEN, AndnaErr

app = Flask(__name__)


@app.route("/verify", methods=["POST"])
def verify():
    """Verify an AN-DNA vNext Phase 1 frame."""
    body = request.get_data()

    if len(body) != FRAME_V2_LEN:
        return jsonify({
            "ok": False,
            "error_code": AndnaErr.ERR_LENGTH,
            "error_msg": f"expected {FRAME_V2_LEN} bytes, got {len(body)}",
        }), 400

    # ── This is the actual verification call ──
    engine = get_engine()  # reads VERIFY_ENGINE env var, cached
    result = engine.verify_frame_v2(body)

    if result.ok:
        return jsonify({"ok": True}), 200
    else:
        return jsonify({
            "ok": False,
            "error_code": result.error_code,
            "error_msg": result.error_msg,
        }), 403


@app.route("/health", methods=["GET"])
def health():
    engine = get_engine()
    return jsonify({
        "status": "ok",
        "engine": engine.name,
        "verify_engine_env": os.environ.get("VERIFY_ENGINE", "python"),
    })


if __name__ == "__main__":
    engine = get_engine()
    print(f"AN-DNA verifier starting (engine={engine.name})")
    app.run(host="0.0.0.0", port=8080)
