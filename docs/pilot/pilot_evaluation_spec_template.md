# Pilot Evaluation Spec (Template) — AN-DNA R1

## Goal
Define a 2–4 week evaluation that lets a DevSecOps reviewer validate:
- pinned-lane determinism
- audit-chain tamper evidence
- replayability and evidence export

## Scope
- In-scope: Proof Pack artifacts; fixture parity run; T1/T2/T3 harness outputs
- Out-of-scope: new protocol features; performance tuning beyond basic smoke; integrations beyond reading exported artifacts

## Success criteria
- Reviewer reproduces the frozen verification_digest using the fixture
- Reviewer can trigger a red-failure by flipping 1 byte in `andna_audit.jsonl`
- Reviewer confirms validator failure is deterministic and explainable

## Deliverables
- evaluation notes + reproduction steps
- any issues found (with reproduction)
- recommendation: proceed / proceed-with-conditions / no-go
