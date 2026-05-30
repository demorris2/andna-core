# R1 Integrity Statement (LOCKED)

AN-DNA R1 produces an authoritative, tamper-evident audit chain in **andna_audit.jsonl**, using monotonic sequencing and **sha3-256** hash chaining. Human-readable logs may also be produced for convenience, but **only the authoritative chain** supports integrity claims.

# Tamper Statement (LOCKED)

If any byte changes in the authoritative audit chain or exported evidence artifacts, validation fails (either via the audit-chain validator or via digest mismatch checks).

# Boundary Statement (LOCKED)

These claims apply **within the pinned verification lane** and for the artifact classes demonstrated in the Proof Pack (fixture frame, evidence bundle, and authoritative audit chain).

# Gate 2 T3 (LOCKED): Order Invariance Under Record Permutation

**R1 Rule:** The authoritative chain is order-sensitive. Any permutation, duplication, deletion, or seq-gap must FAIL validation.

## Acceptance checks
1) Swap two lines → FAIL
2) Duplicate a line → FAIL
3) Delete a line → FAIL
4) Edit seq to create a gap (e.g., 0,2) → FAIL

**R1 recommendation:** FAIL on any permutation. This preserves “single writer owns order” semantics and keeps audit review simple.
