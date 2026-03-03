#!/bin/bash
# AN-DNA Gate 1 Validation Script
# Usage: ./gate1_validate.sh

echo "[1/3] Building clean environment..."
docker build -t andna-verifier .

echo "[2/3] Extracting binary fingerprint..."
# This is the hash we compare against Host A
docker run --entrypoint sha256sum andna-verifier /usr/local/lib/libandna_ffi.so

echo "[3/3] Executing test suite..."
docker run andna-verifier