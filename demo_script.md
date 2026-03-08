# AN-DNA 5-Minute Proof Cycle

# 1. Copy the golden fixture to ensure cross-host verification parity
cp demo/fixtures/sample_frame.bin sample_frame.bin

# 2. Verify the clean frame (Produces ACCEPT)
andna verify sample_frame.bin

# 3. Tamper with the frame and verify the corrupted version (Produces REJECT)
andna tamper sample_frame.bin tampered_frame.bin
andna verify tampered_frame.bin

# 4. Deterministic Replay: Assert the log against the exact frame bytes
andna replay verification_log.json --frame sample_frame.bin

# 5. Export the Gate 2 Evidence Artifacts
andna export evidence/