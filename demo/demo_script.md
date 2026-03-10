# AN-DNA R1 Demo (Parity / Proof Pack)

## Parity run (no randomness)
1) Verify the golden fixture:
```
andna verify demo/fixtures/sample_frame.bin
```

2) Tamper and verify reject:
```
cp demo/fixtures/sample_frame.bin tampered_frame.bin
andna tamper tampered_frame.bin tampered_frame.bin
andna verify tampered_frame.bin
```

3) Replay + re-verify the same bytes:
```
andna replay verification_log.json --frame demo/fixtures/sample_frame.bin
```

4) Export evidence:
```
andna export evidence/
```

## What to report
- verification_digest (must equal baseline for this fixture)
- contract_version, schema_version
- confirmation: “If you change one byte in andna_audit.jsonl, validation fails.”
