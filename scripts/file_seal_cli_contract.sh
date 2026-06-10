#!/usr/bin/env bash
set -euo pipefail

# AN-DNA file-seal CLI contract test.
# Style rule: NO backslash line continuations anywhere in this script. Pasted edits have
# twice destroyed continuation backslashes / '$' characters; single-line commands are
# immune. Keep it that way.

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
if [[ "$OSTYPE" == "msys" || "$OSTYPE" == "win32" ]]; then
  BIN="$ROOT/target/debug/andna.exe"
else
  BIN="$ROOT/target/debug/andna"
fi

cd "$ROOT"

cleanup() {
  rm -rf .andna
  rm -f sample.txt sample.tampered.txt
  rm -f sample.txt.andna-seal.json sample.txt.tampered-manifest.andna-seal.json sample.txt.bad-frame.andna-seal.json
  rm -f sample.registry.json empty.registry.json verifier.registry.json
  rm -f sample.verify.json sample.verify2.json sample.verify.tampered.json sample.verify.json.andna-seal.json
}

echo "== AN-DNA file-seal CLI contract test =="

cargo build -p ffi-cli --locked --features "oqs-backend fips-integrity-stub"

if [[ ! -x "$BIN" ]]; then
  echo "error: expected CLI binary at $BIN" >&2
  exit 2
fi

cleanup

echo "hello AN-DNA CLI contract" > sample.txt

echo
echo "== init-sealer =="
"$BIN" init-sealer --profile .andna/sealer-profile.json --epoch 7

echo
echo "== seal-file =="
"$BIN" seal-file sample.txt --profile .andna/sealer-profile.json --out sample.txt.andna-seal.json --content-type text/plain --registry-out sample.registry.json

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
VERIFY_OUT="$("$BIN" verify-file sample.txt --seal sample.txt.andna-seal.json --registry sample.registry.json --evidence-out sample.verify.json)"
echo "$VERIFY_OUT"

grep -q "AUTHENTIC:             yes" <<<"$VERIFY_OUT"
grep -q "UNCHANGED:             yes" <<<"$VERIFY_OUT"
grep -q "AUTHORIZED:            yes" <<<"$VERIFY_OUT"
grep -q "RESULT:                ACCEPT" <<<"$VERIFY_OUT"

test -f sample.verify.json

echo
echo "== evidence record matches the v1 contract =="
grep -q '"schema_version": "andna-seal-evidence-v1"' sample.verify.json
grep -q '"result": "ACCEPT"' sample.verify.json
grep -q '"evidence_digest_hex"' sample.verify.json
echo "evidence schema/result/digest fields present"

echo
echo "== evidence determinism: second run, different runtime, same digest =="
"$BIN" verify-file sample.txt --seal sample.txt.andna-seal.json --registry sample.registry.json --evidence-out sample.verify2.json > /dev/null

python - <<'PY'
import json
a = json.load(open("sample.verify.json"))
b = json.load(open("sample.verify2.json"))
assert a["deterministic"] == b["deterministic"], "deterministic sections differ"
assert a["evidence_digest_hex"] == b["evidence_digest_hex"], "evidence digests differ"
print("evidence deterministic section + digest: identical across runs")
PY

echo
echo "== evidence attestation: create verifier profile, attest, verify attestation =="
"$BIN" init-sealer --profile .andna/verifier-profile.json --epoch 3

"$BIN" verify-file sample.txt --seal sample.txt.andna-seal.json --registry sample.registry.json --evidence-out sample.verify.json --attest-profile .andna/verifier-profile.json --attest-registry-out verifier.registry.json > /dev/null

test -f sample.verify.json.andna-seal.json
test -f verifier.registry.json

ATTEST_OUT="$("$BIN" verify-file sample.verify.json --seal sample.verify.json.andna-seal.json --registry verifier.registry.json)"
echo "$ATTEST_OUT"

grep -q "AUTHENTIC:             yes" <<<"$ATTEST_OUT"
grep -q "UNCHANGED:             yes" <<<"$ATTEST_OUT"
grep -q "AUTHORIZED:            yes" <<<"$ATTEST_OUT"
grep -q "RESULT:                ACCEPT" <<<"$ATTEST_OUT"

echo
echo "== tampered evidence record fails its attestation =="
python - <<'PY'
import json
obj = json.load(open("sample.verify.json"))
obj["deterministic"]["result"] = "REJECT"  # forge the record
json.dump(obj, open("sample.verify.tampered.json", "w"), indent=2)
PY

set +e
FORGED_OUT="$("$BIN" verify-file sample.verify.tampered.json --seal sample.verify.json.andna-seal.json --registry verifier.registry.json 2>&1)"
FORGED_CODE=$?
set -e
echo "$FORGED_OUT"

if [[ "$FORGED_CODE" -ne 1 ]]; then
  echo "error: expected forged-evidence verify exit code 1, got $FORGED_CODE" >&2
  exit 1
fi

grep -q "AUTHENTIC:             yes" <<<"$FORGED_OUT"
grep -q "UNCHANGED:             no" <<<"$FORGED_OUT"
grep -q "RESULT:                REJECT" <<<"$FORGED_OUT"

echo
echo "== verify-file tampered file + authorized registry =="
cp sample.txt sample.tampered.txt
echo "tamper" >> sample.tampered.txt

set +e
TAMPER_OUT="$("$BIN" verify-file sample.tampered.txt --seal sample.txt.andna-seal.json --registry sample.registry.json 2>&1)"
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
EMPTY_REG_OUT="$("$BIN" verify-file sample.txt --seal sample.txt.andna-seal.json --registry empty.registry.json 2>&1)"
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
MISSING_OUT="$("$BIN" verify-file missing.txt --seal missing.andna-seal.json --registry missing.registry.json 2>&1)"
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
cleanup

echo
echo "PASS: file-seal CLI contract"
