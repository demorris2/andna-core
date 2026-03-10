# Gate 2 T3 (LOCKED): Order Invariance Under Record Permutation

**R1 Rule:** The authoritative chain is order-sensitive. Any permutation, duplication, deletion, or seq-gap must FAIL validation.

## Acceptance checks
1) Swap two lines → FAIL
2) Duplicate a line → FAIL
3) Delete a line → FAIL
4) Edit seq to create a gap (e.g., 0,2) → FAIL

**R1 recommendation:** FAIL on any permutation. This preserves “single writer owns order” semantics and keeps audit review simple.
