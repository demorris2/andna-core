# PR Summary: Document File-Seal Evidence v1 and Operator Contract

## Summary

Adds documentation for the now-green AN-DNA file-seal lane:

- stable `andna-seal-evidence-v1` evidence contract
- CLI demo and operator walkthrough
- claim boundaries for public/product language
- CI lane explanation
- README-ready file-seal summary

## Why

The file-seal workflow is now CI-backed and should be documented before further CLI expansion. The documentation captures what is currently proven, what is intentionally out of scope, and how to validate the milestone locally.

## What is documented

- `verify-file --evidence-out` top-level evidence shape
- deterministic vs runtime evidence fields
- evidence digest rule
- replay and tamper expectations
- evidence attestation boundary
- four-command CLI surface
- expected ACCEPT/REJECT outcomes
- script-based operator contract rationale
- R2 OQS isolation rationale
- software-profile sealer boundaries

## Validation references

Recommended local validation:

```bash
cargo fmt --all
cargo test -p andna-seal --locked
cargo test -p andna-pipeline --locked
bash scripts/file_seal_cli_contract.sh
```

Expected final contract output:

```text
PASS: file-seal CLI contract
```

## Claim boundary

This PR does not claim hardware custody, clone resistance, enterprise IAM, file encryption, FIPS validation, ACVP readiness, or replacement of Sigstore/SLSA/TUF/in-toto.
