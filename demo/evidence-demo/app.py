#!/usr/bin/env python3
"""AN-DNA File-Seal Evidence Demo UI.

Architecture rule: this program is a thin local GUI shell over the `andna` CLI.
It invokes the CLI via subprocess, reads exit codes and evidence JSON, and renders
results. It contains no verification logic, no frame parsing for validity
decisions, and no cryptography.
"""

from __future__ import annotations

import atexit
import html
import json
import os
import pathlib
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import urlparse

HOST = "127.0.0.1"
PORT = int(os.environ.get("ANDNA_DEMO_PORT", "8765"))

# Task 3 deterministic demo constants. Override with ANDNA_DEMO_SEED_HEX and
# ANDNA_DEMO_DEVICE_ID16_HEX if a downstream test fixture rotates them.
TEST_SEED_HEX = os.environ.get(
    "ANDNA_DEMO_SEED_HEX",
    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
)
TEST_DEVICE_ID16_HEX = os.environ.get(
    "ANDNA_DEMO_DEVICE_ID16_HEX",
    "00112233445566778899aabbccddeeff",
)
TEST_EPOCH = os.environ.get("ANDNA_DEMO_EPOCH", "7")
BUILD_COMMAND = 'cargo build -p ffi-cli --locked --features "oqs-backend fips-integrity-stub"'
FOOTER_CLAIM = (
    "AN-DNA File-Seal demo — software-profile identity; integrity/authenticity binding only; "
    "this does not encrypt files. See docs/file-seal/file-seal-claim-boundaries.md."
)
SAMPLE_BYTES = (
    b"AN-DNA file-seal evidence demo sample\n"
    b"This file is intentionally simple so the UI can demonstrate ACCEPT/REJECT behavior.\n"
)
TAMPER_BYTES = b"\n-- ANDNA DEMO TAMPER BYTES --\n"


def repo_root() -> pathlib.Path:
    return pathlib.Path(__file__).resolve().parents[2]


def resolve_cli(root: pathlib.Path) -> pathlib.Path:
    env_path = os.environ.get("ANDNA_BIN")
    candidates: list[pathlib.Path] = []
    if env_path:
        candidates.append(pathlib.Path(env_path).expanduser())
    candidates.append(root / "target" / "debug" / "andna.exe")
    candidates.append(root / "target" / "debug" / "andna")

    for candidate in candidates:
        resolved = candidate if candidate.is_absolute() else (root / candidate)
        if resolved.exists() and resolved.is_file():
            return resolved

    searched = "\n".join(f"  - {p if p.is_absolute() else root / p}" for p in candidates)
    print("error: expected AN-DNA CLI binary but none was found", file=sys.stderr)
    print(f"searched:\n{searched}", file=sys.stderr)
    print("build it with this exact command:", file=sys.stderr)
    print(f"  {BUILD_COMMAND}", file=sys.stderr)
    sys.exit(2)


class DemoState:
    def __init__(self, cli: pathlib.Path, workdir: pathlib.Path) -> None:
        self.cli = cli
        self.workdir = workdir
        self.sample = workdir / "sample.txt"
        self.sidecar = workdir / "sample.txt.andna-seal.json"
        self.registry = workdir / "sample.registry.json"
        self.evidence = workdir / "sample.verify.json"
        self.last_action = "Ready"
        self.last_stdout = ""
        self.last_error = ""
        self.last_exit_code: int | None = None
        self.last_decision = "IDLE"
        self.tampered = False
        self.show_evidence = False
        self.evidence_obj: dict[str, Any] | None = None
        self.reset_sample()

    def reset_sample(self) -> None:
        self.sample.write_bytes(SAMPLE_BYTES)
        self.tampered = False

    def clear_outputs(self) -> None:
        for path in (self.sidecar, self.registry, self.evidence):
            try:
                path.unlink()
            except FileNotFoundError:
                pass
        self.evidence_obj = None
        self.last_exit_code = None
        self.last_decision = "IDLE"
        self.last_stdout = ""
        self.last_error = ""
        self.show_evidence = False

    def run_cli(self, args: list[str]) -> subprocess.CompletedProcess[str]:
        cmd = [str(self.cli), *args]
        return subprocess.run(
            cmd,
            cwd=str(self.workdir),
            encoding="utf-8",
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            check=False,
        )

    def seal(self) -> None:
        self.reset_sample()
        self.clear_outputs()
        self.last_action = "Seal File"
        seal_result = self.run_cli(
            [
                "seal-file",
                str(self.sample),
                "--seed-hex",
                TEST_SEED_HEX,
                "--device-id16-hex",
                TEST_DEVICE_ID16_HEX,
                "--epoch",
                TEST_EPOCH,
                "--out",
                str(self.sidecar),
                "--content-type",
                "text/plain",
                "--registry-out",
                str(self.registry),
            ]
        )
        self.last_exit_code = seal_result.returncode
        self.last_stdout = seal_result.stdout
        self.last_error = ""
        self.last_decision = "SEALED" if seal_result.returncode == 0 else "ERROR"
        if seal_result.returncode != 0:
            self.last_error = "seal-file failed; the CLI output is shown below."
            return

        inspect_result = self.run_cli(["inspect-seal", str(self.sidecar)])
        self.last_stdout = seal_result.stdout + "\n" + inspect_result.stdout
        if inspect_result.returncode != 0:
            self.last_exit_code = inspect_result.returncode
            self.last_decision = "ERROR"
            self.last_error = "inspect-seal failed after seal-file; the CLI output is shown below."

    def tamper(self) -> None:
        self.last_action = "Tamper File"
        if not self.sample.exists():
            self.reset_sample()
        with self.sample.open("ab") as f:
            f.write(TAMPER_BYTES)
        self.tampered = True
        self.show_evidence = False
        self.last_decision = "TAMPERED"
        self.last_exit_code = None
        self.last_error = ""
        self.last_stdout = f"Appended {len(TAMPER_BYTES)} tamper bytes to {self.sample.name}."

    def verify(self) -> None:
        self.last_action = "Verify File"
        self.show_evidence = False
        self.evidence_obj = None
        if not self.sidecar.exists() or not self.registry.exists():
            self.last_decision = "ERROR"
            self.last_exit_code = 2
            self.last_error = "Seal File must run before Verify File."
            self.last_stdout = ""
            return

        try:
            self.evidence.unlink()
        except FileNotFoundError:
            pass

        result = self.run_cli(
            [
                "verify-file",
                str(self.sample),
                "--seal",
                str(self.sidecar),
                "--registry",
                str(self.registry),
                "--evidence-out",
                str(self.evidence),
            ]
        )
        self.last_exit_code = result.returncode
        self.last_stdout = result.stdout
        self.last_error = ""
        if result.returncode == 0:
            self.last_decision = "ACCEPT"
        elif result.returncode == 1:
            self.last_decision = "REJECT"
        else:
            self.last_decision = "ERROR"
            self.last_error = "verify-file returned exit code 2; the CLI output is shown below."

        if self.evidence.exists():
            try:
                self.evidence_obj = json.loads(self.evidence.read_text(encoding="utf-8"))
            except json.JSONDecodeError as exc:
                self.last_error = f"Evidence JSON could not be parsed for rendering: {exc}"

    def evidence_view(self) -> None:
        self.last_action = "Show Evidence"
        if not self.evidence_obj and self.evidence.exists():
            try:
                self.evidence_obj = json.loads(self.evidence.read_text(encoding="utf-8"))
            except json.JSONDecodeError as exc:
                self.last_error = f"Evidence JSON could not be parsed for rendering: {exc}"
                self.show_evidence = False
                return
        if not self.evidence_obj:
            self.last_error = "Verify File must produce evidence before Show Evidence can render it."
            self.show_evidence = False
            return
        self.last_error = ""
        self.show_evidence = True


ROOT = repo_root()
CLI = resolve_cli(ROOT)
WORKDIR = pathlib.Path(tempfile.mkdtemp(prefix="andna-evidence-demo-"))
STATE = DemoState(CLI, WORKDIR)


def cleanup() -> None:
    shutil.rmtree(WORKDIR, ignore_errors=True)


atexit.register(cleanup)


def to_display(value: Any) -> str:
    if isinstance(value, bool):
        return "yes" if value else "no"
    if value is None:
        return "not present"
    return str(value)


def get_field(obj: dict[str, Any] | None, key: str) -> Any:
    if not obj:
        return None
    deterministic = obj.get("deterministic")
    if isinstance(deterministic, dict) and key in deterministic:
        return deterministic.get(key)
    return obj.get(key)


def verdict_rows(state: DemoState) -> str:
    obj = state.evidence_obj
    authentic = to_display(get_field(obj, "authentic"))
    unchanged = to_display(get_field(obj, "unchanged"))
    authorized = to_display(get_field(obj, "authorized"))
    unchanged_detail = get_field(obj, "unchanged_detail")
    unchanged_extra = ""
    if unchanged_detail is not None:
        unchanged_extra = f"<div class='detail'>{html.escape(to_display(unchanged_detail))}</div>"
    return f"""
    <div class="verdict-grid">
      <div class="label">AUTHENTIC</div><div class="value">{html.escape(authentic)}</div>
      <div class="label">UNCHANGED</div><div class="value">{html.escape(unchanged)}{unchanged_extra}</div>
      <div class="label">AUTHORIZED</div><div class="value">{html.escape(authorized)}</div>
    </div>
    """


def evidence_sections(state: DemoState) -> str:
    obj = state.evidence_obj
    if not obj:
        return "<p class='muted'>No evidence JSON loaded. Run Verify File first.</p>"

    deterministic = obj.get("deterministic", {})
    runtime = obj.get("runtime", {})
    digest = obj.get("evidence_digest_hex", "not present")
    everything_else = {
        k: v
        for k, v in obj.items()
        if k not in {"deterministic", "runtime", "evidence_digest_hex"}
    }

    return f"""
    <div class="caption">digest covers the deterministic section only; runtime fields are recorded but digest-exempt.</div>
    <div class="digest"><span>evidence_digest_hex</span><code>{html.escape(str(digest))}</code></div>
    <div class="evidence-columns">
      <section class="evidence-box deterministic">
        <h3>Deterministic section</h3>
        <pre>{html.escape(json.dumps(deterministic, indent=2, sort_keys=True))}</pre>
      </section>
      <section class="evidence-box runtime">
        <h3>Runtime section</h3>
        <pre>{html.escape(json.dumps(runtime, indent=2, sort_keys=True))}</pre>
      </section>
    </div>
    <section class="evidence-box other">
      <h3>Record metadata</h3>
      <pre>{html.escape(json.dumps(everything_else, indent=2, sort_keys=True))}</pre>
    </section>
    """


def render_page(state: DemoState) -> bytes:
    decision_class = state.last_decision.lower()
    tamper_badge = "<span class='badge bad'>tampered</span>" if state.tampered else "<span class='badge good'>clean</span>"
    evidence_digest = ""
    if state.evidence_obj:
        digest = state.evidence_obj.get("evidence_digest_hex")
        if digest:
            evidence_digest = f"<p class='small'><strong>Evidence digest:</strong> <code>{html.escape(str(digest))}</code></p>"

    if state.show_evidence:
        panel_body = evidence_sections(state)
    else:
        panel_body = f"""
        <div class="decision {decision_class}">{html.escape(state.last_decision)}</div>
        {verdict_rows(state) if state.last_decision in {"ACCEPT", "REJECT"} else ""}
        {evidence_digest}
        <pre class="stdout">{html.escape(state.last_stdout)}</pre>
        """

    error_html = f"<div class='error'>{html.escape(state.last_error)}</div>" if state.last_error else ""
    body = f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>AN-DNA File-Seal Evidence Demo</title>
<style>
:root {{ color-scheme: dark; --bg:#0b1020; --panel:#121a2d; --panel2:#18213a; --text:#e9eefb; --muted:#9aa7c7; --line:#263352; --green:#4ade80; --red:#fb7185; --amber:#fbbf24; }}
* {{ box-sizing: border-box; }}
body {{ margin:0; font-family: ui-sans-serif, system-ui, -apple-system, Segoe UI, Arial, sans-serif; background: radial-gradient(circle at top left, #1d2a4a, var(--bg) 38%); color:var(--text); }}
main {{ max-width: 1180px; margin: 0 auto; padding: 32px 24px; }}
header {{ display:flex; justify-content:space-between; gap:24px; align-items:flex-start; margin-bottom:24px; }}
h1 {{ margin:0 0 8px; font-size:32px; letter-spacing:-0.03em; }}
.sub {{ color:var(--muted); margin:0; line-height:1.5; }}
.meta {{ text-align:right; color:var(--muted); font-size:13px; line-height:1.5; }}
.card {{ background:rgba(18,26,45,0.92); border:1px solid var(--line); border-radius:18px; box-shadow:0 20px 60px rgba(0,0,0,.25); }}
.controls {{ display:grid; grid-template-columns: repeat(4, minmax(140px, 1fr)); gap:12px; padding:16px; margin-bottom:18px; }}
button {{ width:100%; border:0; border-radius:14px; padding:14px 16px; font-weight:700; color:#07111f; background:#dbeafe; cursor:pointer; font-size:15px; }}
button:hover {{ filter:brightness(1.08); }}
button.tamper {{ background:#fecdd3; }}
button.verify {{ background:#bbf7d0; }}
button.evidence {{ background:#fde68a; }}
.panel {{ padding:22px; min-height:420px; }}
.panel-head {{ display:flex; justify-content:space-between; gap:16px; align-items:center; margin-bottom:16px; }}
.panel-head h2 {{ margin:0; font-size:18px; }}
.badge {{ display:inline-block; border-radius:999px; padding:5px 10px; font-size:12px; font-weight:800; text-transform:uppercase; letter-spacing:.06em; }}
.badge.good {{ color:#052e16; background:var(--green); }}
.badge.bad {{ color:#3f0713; background:var(--red); }}
.decision {{ font-size:72px; line-height:1; font-weight:900; letter-spacing:-.06em; margin:8px 0 18px; }}
.decision.accept {{ color:var(--green); }}
.decision.reject {{ color:var(--red); }}
.decision.error {{ color:var(--amber); }}
.decision.idle, .decision.sealed, .decision.tampered {{ color:#bfdbfe; }}
.verdict-grid {{ display:grid; grid-template-columns: 190px 1fr; border:1px solid var(--line); border-radius:14px; overflow:hidden; margin:14px 0 18px; }}
.verdict-grid .label, .verdict-grid .value {{ padding:13px 15px; border-bottom:1px solid var(--line); }}
.verdict-grid .label {{ background:var(--panel2); color:var(--muted); font-weight:800; letter-spacing:.08em; font-size:12px; }}
.verdict-grid .value {{ font-size:18px; font-weight:800; }}
.verdict-grid .label:nth-last-child(2), .verdict-grid .value:last-child {{ border-bottom:0; }}
.detail {{ margin-top:4px; color:var(--muted); font-size:13px; font-weight:500; }}
.stdout {{ background:#070b14; border:1px solid var(--line); border-radius:14px; padding:14px; overflow:auto; max-height:260px; color:#d1d5db; }}
.error {{ border:1px solid #7f1d1d; background:#450a0a; color:#fecaca; padding:12px 14px; border-radius:12px; margin-bottom:14px; font-weight:700; }}
.small {{ color:var(--muted); font-size:13px; }}
code {{ color:#bfdbfe; overflow-wrap:anywhere; }}
.caption {{ color:#fde68a; background:#3b2f10; border:1px solid #785f16; border-radius:12px; padding:12px 14px; margin-bottom:14px; }}
.digest {{ display:grid; grid-template-columns: 210px 1fr; gap:12px; align-items:center; background:#07111f; border:1px solid var(--line); border-radius:12px; padding:12px 14px; margin-bottom:14px; }}
.digest span {{ color:var(--muted); font-weight:800; }}
.evidence-columns {{ display:grid; grid-template-columns: 1fr 1fr; gap:14px; }}
.evidence-box {{ border:1px solid var(--line); border-radius:14px; overflow:hidden; background:#080d18; margin-bottom:14px; }}
.evidence-box h3 {{ margin:0; padding:12px 14px; background:var(--panel2); font-size:14px; }}
.evidence-box.deterministic h3 {{ color:var(--green); }}
.evidence-box.runtime h3 {{ color:#93c5fd; }}
.evidence-box.other h3 {{ color:var(--muted); }}
.evidence-box pre {{ margin:0; padding:14px; overflow:auto; max-height:360px; }}
footer {{ margin-top:18px; color:var(--muted); font-size:13px; text-align:center; }}
@media (max-width: 820px) {{ .controls, .evidence-columns {{ grid-template-columns: 1fr; }} header {{ display:block; }} .meta {{ text-align:left; margin-top:12px; }} .decision {{ font-size:52px; }} }}
</style>
</head>
<body>
<main>
  <header>
    <div>
      <h1>AN-DNA File-Seal Evidence Demo</h1>
      <p class="sub">Local GUI shell over the <code>andna</code> CLI. The CLI is the sole authoritative verification engine.</p>
    </div>
    <div class="meta">
      <div>CLI: <code>{html.escape(str(state.cli))}</code></div>
      <div>Temp workdir: <code>{html.escape(str(state.workdir))}</code></div>
      <div>Sample state: {tamper_badge}</div>
    </div>
  </header>

  <section class="card controls">
    <form method="post" action="/seal"><button type="submit">Seal File</button></form>
    <form method="post" action="/tamper"><button class="tamper" type="submit">Tamper File</button></form>
    <form method="post" action="/verify"><button class="verify" type="submit">Verify File</button></form>
    <form method="post" action="/evidence"><button class="evidence" type="submit">Show Evidence</button></form>
  </section>

  <section class="card panel">
    <div class="panel-head">
      <h2>{html.escape(state.last_action)}</h2>
      <div class="small">Exit code: {html.escape(to_display(state.last_exit_code))}</div>
    </div>
    {error_html}
    {panel_body}
  </section>

  <footer>{html.escape(FOOTER_CLAIM)}</footer>
</main>
</body>
</html>
"""
    return body.encode("utf-8")


class Handler(BaseHTTPRequestHandler):
    server_version = "AndnaEvidenceDemo/1.0"

    def log_message(self, fmt: str, *args: Any) -> None:
        timestamp = time.strftime("%H:%M:%S")
        print(f"[{timestamp}] {self.address_string()} {fmt % args}")

    def do_GET(self) -> None:
        path = urlparse(self.path).path
        if path != "/":
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b"not found")
            return
        page = render_page(STATE)
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(page)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(page)

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length", "0") or "0")
        if length:
            self.rfile.read(length)
        path = urlparse(self.path).path
        if path == "/seal":
            STATE.seal()
        elif path == "/tamper":
            STATE.tamper()
        elif path == "/verify":
            STATE.verify()
        elif path == "/evidence":
            STATE.evidence_view()
        else:
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b"not found")
            return
        self.send_response(303)
        self.send_header("Location", "/")
        self.end_headers()


def main() -> int:
    httpd = ThreadingHTTPServer((HOST, PORT), Handler)
    httpd.daemon_threads = True
    url = f"http://{HOST}:{PORT}/"
    print("AN-DNA File-Seal Evidence Demo")
    print(f"CLI: {CLI}")
    print(f"Temp workdir: {WORKDIR}")
    print(f"Serving only on {url}")
    print("Press Ctrl+C to stop; temp artifacts are cleaned on exit.")

    def open_browser() -> None:
        webbrowser.open(url)

    threading.Timer(0.5, open_browser).start()

    def stop(signum: int, frame: Any) -> None:
        raise KeyboardInterrupt

    signal.signal(signal.SIGTERM, stop)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping demo server.")
    finally:
        httpd.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
