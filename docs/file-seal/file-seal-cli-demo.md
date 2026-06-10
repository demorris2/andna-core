# AN-DNA File-Seal CLI Demo

Status: CI-gated  
Primary script: `scripts/file_seal_cli_contract.sh`  
CLI surface: `init-sealer`, `seal-file`, `inspect-seal`, `verify-file`

## What this demo proves

This demo proves that AN-DNA can:

1. initialize a local software-profile sealer,
2. seal a file into a detached sidecar,
3. inspect the sidecar structure,
4. verify authenticity,
5. check that the file is unchanged,
6. evaluate local authorization against a registry snapshot,
7. emit a stable evidence record,
8. attest that evidence record,
9. reject a forged evidence record, and
10. reject expected tamper and authorization-failure cases.

The important operator distinction is:

```text
AUTHENTIC != UNCHANGED != AUTHORIZED
```

The final decision is only `ACCEPT` when the required checks pass together.

## Prerequisites

Build the CLI with the OQS backend and the current integrity stub feature set:

```bash
cargo build -p ffi-cli --locked --features "oqs-backend fips-integrity-stub"
```

The contract script resolves the built binary portably:

```text
target/debug/andna      # Linux/macOS
target/debug/andna.exe  # Windows
```

## Manual walkthrough

From the repository root:

```bash
echo "hello AN-DNA CLI contract" > sample.txt
```

Initialize a demo/MVP software-profile sealer:

```bash
./target/debug/andna init-sealer \
  --profile .andna/sealer-profile.json \
  --epoch 7
```

Seal the file and produce a registry snapshot:

```bash
./target/debug/andna seal-file sample.txt \
  --profile .andna/sealer-profile.json \
  --out sample.txt.andna-seal.json \
  --content-type text/plain \
  --registry-out sample.registry.json
```

Inspect the sidecar:

```bash
./target/debug/andna inspect-seal sample.txt.andna-seal.json
```

Expected valid-sidecar indicators:

```text
Frame length status:   ok
ctx_hash matches:      yes
Frame epoch:           7
T_E epoch:             7
```

Verify the clean file against the authorized registry:

```bash
./target/debug/andna verify-file sample.txt \
  --seal sample.txt.andna-seal.json \
  --registry sample.registry.json \
  --evidence-out sample.verify.json
```

Expected operator result:

```text
AUTHENTIC:             yes
UNCHANGED:             yes
AUTHORIZED:            yes
RESULT:                ACCEPT
```

The evidence file should include:

```json
{
  "schema_version": "andna-seal-evidence-v1",
  "deterministic": {
    "result": "ACCEPT"
  },
  "evidence_digest_hex": "..."
}
```

## Evidence determinism check

Run verification a second time and compare the deterministic section plus digest:

```bash
./target/debug/andna verify-file sample.txt \
  --seal sample.txt.andna-seal.json \
  --registry sample.registry.json \
  --evidence-out sample.verify2.json > /dev/null

python - <<'PY'
import json

a = json.load(open("sample.verify.json"))
b = json.load(open("sample.verify2.json"))

assert a["deterministic"] == b["deterministic"], "deterministic sections differ"
assert a["evidence_digest_hex"] == b["evidence_digest_hex"], "evidence digests differ"
print("evidence deterministic section + digest: identical across runs")
PY
```

## Evidence attestation check

Create a verifier profile:

```bash
./target/debug/andna init-sealer \
  --profile .andna/verifier-profile.json \
  --epoch 3
```

Verify the file again, emit evidence, and attest the evidence file:

```bash
./target/debug/andna verify-file sample.txt \
  --seal sample.txt.andna-seal.json \
  --registry sample.registry.json \
  --evidence-out sample.verify.json \
  --attest-profile .andna/verifier-profile.json \
  --attest-registry-out verifier.registry.json > /dev/null
```

Verify the evidence attestation:

```bash
./target/debug/andna verify-file sample.verify.json \
  --seal sample.verify.json.andna-seal.json \
  --registry verifier.registry.json
```

Expected result:

```text
AUTHENTIC:             yes
UNCHANGED:             yes
AUTHORIZED:            yes
RESULT:                ACCEPT
```

Forge the evidence record by changing the deterministic decision:

```bash
python - <<'PY'
import json

obj = json.load(open("sample.verify.json"))
obj["deterministic"]["result"] = "REJECT"
json.dump(obj, open("sample.verify.tampered.json", "w"), indent=2)
PY
```

Verify the forged evidence against the original attestation:

```bash
./target/debug/andna verify-file sample.verify.tampered.json \
  --seal sample.verify.json.andna-seal.json \
  --registry verifier.registry.json
```

Expected result:

```text
AUTHENTIC:             yes
UNCHANGED:             no
RESULT:                REJECT
```

## Negative cases covered by the contract script

The script covers these expected outcomes:

| Case | Expected decision |
| --- | --- |
| Clean file + authorized registry | `ACCEPT` |
| Tampered file + authorized registry | `REJECT` |
| Clean file + empty registry | `REJECT` |
| Tampered manifest | `ctx_hash matches: no` |
| Malformed frame | `Frame length status: bad_length` |
| Missing input | CLI error path, exit code `2` |
| Forged evidence under existing attestation | `UNCHANGED: no`, `RESULT: REJECT` |

## One-command validation

Run:

```bash
bash scripts/file_seal_cli_contract.sh
```

Expected final line:

```text
PASS: file-seal CLI contract
```

## Cleanup

The contract script cleans its own generated demo state. For manual cleanup:

```bash
rm -rf .andna
rm -f sample.txt sample.tampered.txt
rm -f sample.txt.andna-seal.json sample.txt.tampered-manifest.andna-seal.json sample.txt.bad-frame.andna-seal.json
rm -f sample.registry.json empty.registry.json verifier.registry.json
rm -f sample.verify.json sample.verify2.json sample.verify.tampered.json sample.verify.json.andna-seal.json
```

## Safety note

The `.andna/` directory contains software-profile seed material for demo/MVP use. It must not be committed, uploaded, or shared.

The manual-walkthrough commands use \ line continuations. Pasted continuations have
broken twice on the primary dev machine (MINGW64 paste mangling), and operators WILL paste
these blocks. Convert every multi-line command to a single line, matching the contract
script's own declared style rule. Example conversions (apply the same to all):
./target/debug/andna init-sealer --profile .andna/sealer-profile.json --epoch 7
./target/debug/andna seal-file sample.txt --profile .andna/sealer-profile.json --out sample.txt.andna-seal.json --content-type text/plain --registry-out sample.registry.json
./target/debug/andna verify-file sample.txt --seal sample.txt.andna-seal.json --registry sample.registry.json --evidence-out sample.verify.json
Also in the determinism section, change python - <<'PY' to note the fallback:
"use python or python3, whichever your platform provides (the contract script
auto-resolves this)."