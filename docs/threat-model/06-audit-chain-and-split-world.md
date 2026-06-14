# 06 — Audit Chain and Split World

## Built / true today

### Append-only hash-linked local audit log (`andna_audit.jsonl`)

- Each entry is a JSON line containing a `seq` (monotonic integer starting at 0), a
  `prev_hash` (SHA3-256 of the previous entry's canonical bytes), and the event payload.
- Genesis entry (seq 0) has `prev_hash = "0" * 64` (all-zero hex string).
- Log is single-writer; entries are produced by the CLI in sequence during a verification run.
- The chain detects: local tamper (any entry edit changes its hash, breaking the next
  entry's `prev_hash` link), duplication (seq numbers are consecutive), deletion (a gap in
  seq numbers breaks the chain), and reordering (hash links are directional).

### What the audit log does NOT detect

The hash chain is a **local integrity log**, not a distributed ledger. A root adversary who
controls the host can:
- Fork the chain into two consistent histories (one for legitimate auditors, one for the
  adversary's own records) — each fork is internally valid.
- Truncate the log at a chosen entry and produce a fresh chain from that point forward.
- Replace the reference file used to validate the chain.
- Omit specific evidence bundles without breaking the chain (the chain records events, not
  all possible events).

These capabilities define the split-world threat.

## Threat analysis

### Split world / forked log

A root adversary on the host can maintain two separate `andna_audit.jsonl` files, one
presented to auditors and one used internally. Both chains are hash-valid. There is no
external anchor that would allow an auditor to distinguish the authentic chain from the fork.

**Current mitigation:** none against a root adversary with file-system access. Detection
requires an out-of-band comparison (e.g. auditor holds an independent copy of the log from
before the fork point).

### Log truncation

An adversary deletes entries from the end of the log (or all entries) and starts a fresh
chain. The fresh chain is internally valid. Without an external anchor or a previously
exported checkpoint, truncation cannot be detected.

### Reference-file replacement

The audit chain is verified against a reference file held on the same host. If the
reference file is replaced along with the chain, the forged chain validates cleanly.

### Evidence-bundle omission

An adversary omits specific verification events from the log (e.g. a REJECT event for a
suspicious artifact). Omission does not break the hash chain of the remaining entries.
There is no required-event manifest that would detect the gap.

## Not yet built (future mitigations)

- **Periodic external anchoring**: hash the current chain tip into an external, append-only
  store (public ledger, transparency log, or customer-held endpoint) at configurable intervals.
  An anchor makes truncation and forking detectable after the anchor point.
- **Public Merkle / transparency registry**: publish audit roots to a shared log; enables
  cross-operator consistency checks.
- **Witness cosigning**: a second party (external witness service) signs chain checkpoints,
  preventing undetected fork or truncation after the cosigned point.
- **Signed checkpoints**: the local CLI exports signed chain-tip hashes that auditors can
  independently store and compare.
- **Exported audit anchors**: a CLI command to export the current chain tip as a signed,
  portable artifact for auditor custody.

All of the above are strictly future hardening. None are built today.

## Reviewer questions

1. For the pilot use case, is the split-world gap acceptable given that auditors can hold
   independent log copies taken at known-good points?
2. Should the CLI already emit a chain-tip hash on exit (as an anchor hint) without yet
   committing to a full external anchoring protocol?
