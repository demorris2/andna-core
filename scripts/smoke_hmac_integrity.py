#!/usr/bin/env python3
"""
AN-DNA R1 HMAC software-integrity smoke test.

Validates the Path A' runtime flow against a compiled release shared library:

  libandna_ffi.so + libandna_ffi.integrity

Each case runs in a fresh subprocess so the FFI module state machine cannot leak
between tests. This matters because andna_init() transitions to APPROVED or
ERROR and is intentionally sticky for the lifetime of a loaded process.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


ANDNA_ERR_OK = 0
ANDNA_ERR_INTERNAL = 100

ENV_MODULE = "ANDNA_INTEGRITY_MODULE_PATH"
ENV_REF = "ANDNA_INTEGRITY_REF_PATH"


CHILD_CODE = r"""
import ctypes
import sys

lib_path = sys.argv[1]
expected = int(sys.argv[2])

lib = ctypes.CDLL(lib_path)
lib.andna_init.restype = ctypes.c_int

rc = lib.andna_init()
print(f"andna_init rc={rc}")

if rc != expected:
    raise SystemExit(f"expected rc={expected}, got rc={rc}")
"""


def run_case(label: str, lib_path: Path, expected: int, env_updates: dict[str, str] | None) -> None:
    env = os.environ.copy()
    env.pop(ENV_MODULE, None)
    env.pop(ENV_REF, None)

    if env_updates:
        env.update(env_updates)

    print(f"== {label} ==")
    subprocess.run(
        [sys.executable, "-c", CHILD_CODE, str(lib_path), str(expected)],
        env=env,
        check=True,
    )


def tamper_one_byte(src: Path, dst: Path) -> None:
    data = bytearray(src.read_bytes())
    if not data:
        raise RuntimeError(f"cannot tamper empty file: {src}")

    # Do not load this tampered file as a shared object. The clean library is
    # loaded, while ANDNA_INTEGRITY_MODULE_PATH points at this tampered copy.
    # That tests the runtime integrity check without risking ELF loader failure.
    data[-1] ^= 0x01
    dst.write_bytes(data)


def tamper_reference(src: Path, dst: Path) -> None:
    text = src.read_text(encoding="utf-8")
    if "algorithm=HMAC-SHA-256" not in text:
        raise RuntimeError("reference file did not contain expected algorithm line")

    dst.write_text(
        text.replace("algorithm=HMAC-SHA-256", "algorithm=SHA-256", 1),
        encoding="utf-8",
    )


def main() -> int:
    if len(sys.argv) != 3:
        print(
            "usage: smoke_hmac_integrity.py <libandna_ffi.so> <libandna_ffi.integrity>",
            file=sys.stderr,
        )
        return 2

    module = Path(sys.argv[1]).resolve()
    reference = Path(sys.argv[2]).resolve()

    if not module.exists():
        print(f"missing module artifact: {module}", file=sys.stderr)
        return 2

    if not reference.exists():
        print(f"missing integrity reference: {reference}", file=sys.stderr)
        return 2

    with tempfile.TemporaryDirectory(prefix="andna-hmac-smoke-") as tmp:
        tmpdir = Path(tmp)

        clean_module = tmpdir / "libandna_ffi.so"
        clean_ref = tmpdir / "libandna_ffi.integrity"
        tampered_module = tmpdir / "libandna_ffi.tampered.so"
        tampered_ref = tmpdir / "libandna_ffi.tampered.integrity"

        shutil.copy2(module, clean_module)
        shutil.copy2(reference, clean_ref)

        tamper_one_byte(clean_module, tampered_module)
        tamper_reference(clean_ref, tampered_ref)

        run_case(
            label="valid module/reference pair passes",
            lib_path=clean_module,
            expected=ANDNA_ERR_OK,
            env_updates={
                ENV_MODULE: str(clean_module),
                ENV_REF: str(clean_ref),
            },
        )

        run_case(
            label="missing env paths fail closed",
            lib_path=clean_module,
            expected=ANDNA_ERR_INTERNAL,
            env_updates=None,
        )

        run_case(
            label="tampered module bytes fail closed",
            lib_path=clean_module,
            expected=ANDNA_ERR_INTERNAL,
            env_updates={
                ENV_MODULE: str(tampered_module),
                ENV_REF: str(clean_ref),
            },
        )

        run_case(
            label="tampered reference fails closed",
            lib_path=clean_module,
            expected=ANDNA_ERR_INTERNAL,
            env_updates={
                ENV_MODULE: str(clean_module),
                ENV_REF: str(tampered_ref),
            },
        )

    print("HMAC integrity smoke test: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())