# File-Seal MVP

AN-DNA File-Seal is the current operator-facing wedge for the AN-DNA trust-evidence architecture.

It provides a four-command flow:

```bash
andna init-sealer
andna seal-file
andna inspect-seal
andna verify-file
```

The workflow seals a file into a detached sidecar, binds the file manifest into an R1 verification context, checks file unchanged state, evaluates R2 authorization against a registry snapshot, and emits an `ACCEPT` or `REJECT` decision.

The core distinction is:

```text
AUTHENTIC != UNCHANGED != AUTHORIZED
```

A clean authorized file should verify as:

```text
AUTHENTIC:             yes
UNCHANGED:             yes
AUTHORIZED:            yes
RESULT:                ACCEPT
```

A tampered file, unauthorized identity, malformed sidecar, forged evidence file, or missing input should reject.

## Evidence

`verify-file --evidence-out <path>` writes `andna-seal-evidence-v1`, a stable evidence contract with:

- a deterministic replay section
- an evidence digest over the deterministic section
- runtime context fields that are excluded from the digest
- a display summary for human operators

The evidence digest is computed over a domain-separated canonical encoding of the deterministic section, not over JSON formatting.

## Validate locally

```bash
cargo fmt --all
cargo test -p andna-seal --locked
cargo test -p andna-pipeline --locked
bash scripts/file_seal_cli_contract.sh
```

Expected final line:

```text
PASS: file-seal CLI contract
```

## Boundary

The local software-profile sealer is demo/MVP scoped. It is not hardware custody, clone resistance, enterprise IAM, encryption, FIPS validation, or a replacement for Sigstore/SLSA/TUF/in-toto.
