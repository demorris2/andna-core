# Merge/Release Gate Checklist — AN-DNA R1 (Tight)

## A) Technical gates (must be green)
- [ ] Gate 1 hash parity remains green (Host A/B)
- [ ] Gate 2 T1 passes (baseline)
- [ ] Gate 2 T2 passes (tamper fails)
- [ ] Gate 2 T3 passes (permute/dup/delete/gap fail)
- [ ] `andna export` emits:
  - [ ] `andna_audit.jsonl`
  - [ ] `audit_validate.json`
  - [ ] `manifest.json` + `evidence.json`
- [ ] Rust build is zero-warning in CI

## B) Narrative gates (must be locked)
- [ ] `docs/product/r1_evidence_artifacts.md` states authoritative log vs convenience log
- [ ] `demo/demo_script.md` uses fixture path (no gen for parity)
- [ ] Proof Pack prints frozen digest in one place:
  - `85f4dc18777bc2122cf671dce6c2d69d92c80b5d0dbd78a83a644afa1159818d`

## C) Scope firewall
- [ ] No new protocol features
- [ ] No new SKUs
- [ ] AIPMP remains internal only

## Release candidate command recipe
```bash
# 1) confirm CI green for the PR SHA
# 2) tag an RC (example)
git tag -a vnext-phase1-r1-rc1 -m "AN-DNA R1 RC1 (Gate2+Parity+T1/T2/T3)"
git push origin vnext-phase1-r1-rc1

# 3) cut a release from the tag after external review
```
