#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN="$ROOT/target/debug/andna.exe"

cd "$ROOT"

echo "== AN-DNA file-seal CLI contract test =="

cargo build -p ffi-cli --locked \
  --features "oqs-backend fips-integrity-stub"

if [[ ! -x "$BIN" ]]; then
  echo "error: expected CLI binary at $BIN" >&2
  exit 2
fi

rm -rf .andna
rm -f sample.txt \
      sample.tampered.txt \
      sample.txt.andna-seal.json \
      sample.txt.tampered-manifest.andna-seal.json \
      sample.txt.bad-frame.andna-seal.json \
      sample.registry.json \
      sample.verify.json \
      empty.registry.json

echo "hello AN-DNA CLI contract" > sample.txt

echo
echo "== init-sealer =="
"$BIN" init-sealer \
  --profile .andna/sealer-profile.json \
  --epoch 7

echo
echo "== seal-file =="
"$BIN" seal-file sample.txt \
  --profile .andna/sealer-profile.json \
  --out sample.txt.andna-seal.json \
  --content-type text/plain \
  --registry-out sample.registry.json

echo
echo "== inspect-seal valid sidecar =="
INSPECT_OUT="$("$BIN" inspect-seal sample.txt.andna-seal.json)"
echo "$INSPECT_OUT"

grep -q "Frame length status:   ok" <<<"$INSPECT_OUT"
grep -q "ctx_hash matches:      yes" <<<"$INSPECT_OUT"
grep -q "Frame epoch:           7" <<<"$INSPECT_OUT"
grep -q "T_E epoch:             7" <<<"$INSPECT_OUT"

echo
echo "== verify-file clean + authorized registry =="
VERIFY_OUT="$("$BIN" verify-file sample.txt \
  --seal sample.txt.andna-seal.json \
  --registry sample.registry.json \
  --evidence-out sample.verify.json)"
echo "$VERIFY_OUT"

grep -q "AUTHENTIC:             yes" <<<"$VERIFY_OUT"
grep -q "UNCHANGED:             yes" <<<"$VERIFY_OUT"
grep -q "AUTHORIZED:            yes" <<<"$VERIFY_OUT"
grep -q "RESULT:                ACCEPT" <<<"$VERIFY_OUT"

test -f sample.verify.json

echo
echo "== verify-file tampered file + authorized registry =="
cp sample.txt sample.tampered.txt
echo "tamper" >> sample.tampered.txt

set +e
TAMPER_OUT="$("$BIN" verify-file sample.tampered.txt \
  --seal sample.txt.andna-seal.json \
  --registry sample.registry.json 2>&1)"
TAMPER_CODE=$?
set -e

echo "$TAMPER_OUT"

if [[ "$TAMPER_CODE" -ne 1 ]]; then
  echo "error: expected tampered verify exit code 1, got $TAMPER_CODE" >&2
  exit 1
fi

grep -q "AUTHENTIC:             yes" <<<"$TAMPER_OUT"
grep -q "UNCHANGED:             no" <<<"$TAMPER_OUT"
grep -q "AUTHORIZED:            yes" <<<"$TAMPER_OUT"
grep -q "RESULT:                REJECT" <<<"$TAMPER_OUT"

echo
echo "== verify-file clean + empty registry =="
cat > empty.registry.json <<'JSON'
{
  "snapshot_seq": 1,
  "as_of_unix_ms": 1700000000000,
  "policy_version": "empty-registry-v0",
  "entries": []
}
JSON

set +e
EMPTY_REG_OUT="$("$BIN" verify-file sample.txt \
  --seal sample.txt.andna-seal.json \
  --registry empty.registry.json 2>&1)"
EMPTY_REG_CODE=$?
set -e

echo "$EMPTY_REG_OUT"

if [[ "$EMPTY_REG_CODE" -ne 1 ]]; then
  echo "error: expected empty-registry verify exit code 1, got $EMPTY_REG_CODE" >&2
  exit 1
fi

grep -q "AUTHENTIC:             yes" <<<"$EMPTY_REG_OUT"
grep -q "UNCHANGED:             yes" <<<"$EMPTY_REG_OUT"
grep -q "AUTHORIZED:            no" <<<"$EMPTY_REG_OUT"
grep -q "RESULT:                REJECT" <<<"$EMPTY_REG_OUT"

echo
echo "== inspect-seal tampered manifest =="
python - <<'PY'
import json

path = "sample.txt.andna-seal.json"
with open(path, "r", encoding="utf-8") as f:
    obj = json.load(f)

obj["manifest"]["file_name"] = "evil.txt"

with open("sample.txt.tampered-manifest.andna-seal.json", "w", encoding="utf-8") as f:
    json.dump(obj, f, indent=2)
PY

set +e
TAMPER_MANIFEST_OUT="$("$BIN" inspect-seal sample.txt.tampered-manifest.andna-seal.json 2>&1)"
TAMPER_MANIFEST_CODE=$?
set -e

echo "$TAMPER_MANIFEST_OUT"

if [[ "$TAMPER_MANIFEST_CODE" -ne 1 ]]; then
  echo "error: expected tampered-manifest inspect exit code 1, got $TAMPER_MANIFEST_CODE" >&2
  exit 1
fi

grep -q "File name:             evil.txt" <<<"$TAMPER_MANIFEST_OUT"
grep -q "Frame length status:   ok" <<<"$TAMPER_MANIFEST_OUT"
grep -q "ctx_hash matches:      no" <<<"$TAMPER_MANIFEST_OUT"

echo
echo "== inspect-seal bad frame =="
python - <<'PY'
import json

path = "sample.txt.andna-seal.json"
with open(path, "r", encoding="utf-8") as f:
    obj = json.load(f)

obj["frame_hex"] = "deadbeef"

with open("sample.txt.bad-frame.andna-seal.json", "w", encoding="utf-8") as f:
    json.dump(obj, f, indent=2)
PY

set +e
BAD_FRAME_OUT="$("$BIN" inspect-seal sample.txt.bad-frame.andna-seal.json 2>&1)"
BAD_FRAME_CODE=$?
set -e

echo "$BAD_FRAME_OUT"

if [[ "$BAD_FRAME_CODE" -ne 1 ]]; then
  echo "error: expected bad-frame inspect exit code 1, got $BAD_FRAME_CODE" >&2
  exit 1
fi

grep -q "Frame length:          4" <<<"$BAD_FRAME_OUT"
grep -q "Frame length status:   bad_length" <<<"$BAD_FRAME_OUT"
grep -q "Inspection stopped: frame length is not FRAME_V2_LEN." <<<"$BAD_FRAME_OUT"

echo
echo "== verify-file missing input =="
set +e
MISSING_OUT="$("$BIN" verify-file missing.txt \
  --seal missing.andna-seal.json \
  --registry missing.registry.json 2>&1)"
MISSING_CODE=$?
set -e

echo "$MISSING_OUT"

if [[ "$MISSING_CODE" -ne 2 ]]; then
  echo "error: expected missing-input exit code 2, got $MISSING_CODE" >&2
  exit 1
fi

grep -q "error:" <<<"$MISSING_OUT"

echo
echo "== cleanup =="
rm -rf .andna
rm -f sample.txt \
      sample.tampered.txt \
      sample.txt.andna-seal.json \
      sample.txt.tampered-manifest.andna-seal.json \
      sample.txt.bad-frame.andna-seal.json \
      sample.registry.json \
      sample.verify.json \
      empty.registry.json

echo
echo "PASS: file-seal CLI contract"
