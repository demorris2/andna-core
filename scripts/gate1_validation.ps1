# ==============================================================================
# AN-DNA GATE 1 VALIDATION RUNNER
# Purpose: Execute a deterministic build and verify the FFI binary hash.
# ==============================================================================

Write-Host "--- STEP 1: Building Deterministic Docker Image ---" -ForegroundColor Cyan
docker build -t andna-verifier .

Write-Host "`n--- STEP 2: Extracting Binary Fingerprint (SHA-256) ---" -ForegroundColor Cyan
$hash = docker run --rm --entrypoint sha256sum andna-verifier /usr/local/lib/libandna_ffi.so
Write-Host "RESULT: $hash" -ForegroundColor Yellow

Write-Host "`n--- STEP 3: Executing Integrated Test Suite (ML-DSA-44) ---" -ForegroundColor Cyan
docker run --rm andna-verifier

Write-Host "`n--- VALIDATION COMPLETE ---" -ForegroundColor Green
Write-Host "Compare the RESULT hash above with the Host A baseline."