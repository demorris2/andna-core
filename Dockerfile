# =============================================================================
# AN-DNA vNext Phase 1 — Deterministic Docker Build
# Gate 1 acceptance: identical artifact-bundle output across Linux hosts.
# =============================================================================

# 1. PINNED BASE IMAGE (Builder Stage)
FROM debian@sha256:74d56e3931e0d5a1dd51f8c8a2466d21de84a271cd3b5a733b803aa91abf4421 AS builder

# ── Reproducibility: freeze time ──
ENV SOURCE_DATE_EPOCH=1772150400
ENV DEBIAN_FRONTEND=noninteractive
ENV TZ=UTC

# ── Deterministic C-Compiler Flags ──
# Normalizes paths and disables CPU-specific drift (AVX/AVX2 divergence)
ENV CFLAGS="-ffile-prefix-map=/tmp/liboqs=. -ffile-prefix-map=/build=."
ENV CXXFLAGS="-ffile-prefix-map=/tmp/liboqs=. -ffile-prefix-map=/build=."

# ── Pin versions ──
ARG RUST_VERSION=1.93.1
ARG LIBOQS_VERSION=0.10.1

# ── FIPS feature sets ──
# Development lane:
#   fips-integrity-stub is STUB / NON-CONFORMANT and exists only to keep
#   fast local/dev unit tests working.
#
# HMAC lane:
#   fips-integrity-hmac is the real Path A' software-integrity path.
#   It verifies libandna_ffi.so against an associated ANDNA-INTEGRITY-v1
#   reference file.
ARG FIPS_FEATURES_DEV="oqs-backend fips-integrity-stub fips-kat-vectors-embedded"
ARG FIPS_FEATURES_HMAC="oqs-backend fips-integrity-hmac fips-kat-vectors-embedded"

# ── System build dependencies ──
RUN apt-get update -qq && apt-get install -y --no-install-recommends \
    build-essential \
    ca-certificates \
    cmake \
    curl \
    git \
    ninja-build \
    pkg-config \
    python3 \
    libssl-dev \
    llvm-dev \
    libclang-dev \
    clang \
    && rm -rf /var/lib/apt/lists/*

# ── Install Rust (pinned) ──
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | \
    sh -s -- -y --default-toolchain ${RUST_VERSION} --profile minimal
ENV PATH="/root/.cargo/bin:${PATH}"

# ── Build liboqs (pinned & deterministic) ──
RUN git clone --depth 1 --branch ${LIBOQS_VERSION} \
    https://github.com/open-quantum-safe/liboqs.git /tmp/liboqs && \
    cd /tmp/liboqs && \
    mkdir build && cd build && \
    cmake -GNinja \
        -DBUILD_SHARED_LIBS=ON \
        -DCMAKE_BUILD_TYPE=Release \
        -DCMAKE_INSTALL_PREFIX=/usr/local \
        -DOQS_BUILD_ONLY_LIB=ON \
        -DOQS_DIST_BUILD=ON \
        .. && \
    ninja && ninja install && ldconfig && \
    rm -rf /tmp/liboqs

# ── Copy workspace and Build ──
WORKDIR /build
COPY . .

# Force bindgen to find the installed libclang.
# This path reflects the pinned base image / installed LLVM package set.
ENV LIBCLANG_PATH=/usr/lib/llvm-14/lib
ENV LD_LIBRARY_PATH=/usr/local/lib

# Force Rustup to use the pinned Docker lane toolchain even if rust-toolchain.toml
# exists in the repository.
ENV RUSTUP_TOOLCHAIN=${RUST_VERSION}

# ── Build and validate Path A' HMAC software-integrity lane ──
#
# Gate 1 now covers an artifact bundle:
#   1. target/release/libandna_ffi.so
#   2. target/release/libandna_ffi.integrity
#
# The integrity reference is generated from the release .so and then verified by
# loading the release shared object through the ctypes smoke test. The smoke test
# confirms:
#   - valid module/reference pair passes
#   - missing env paths fail closed
#   - tampered module bytes fail closed
#   - tampered reference fails closed
RUN cargo build -p xtask 2>&1 && \
    cargo build -p andna-ffi --release --features "${FIPS_FEATURES_HMAC}" 2>&1 && \
    cargo run -p xtask -- write-integrity-reference \
        target/release/libandna_ffi.so \
        target/release/libandna_ffi.integrity 2>&1 && \
    python3 scripts/smoke_hmac_integrity.py \
        target/release/libandna_ffi.so \
        target/release/libandna_ffi.integrity 2>&1

# ── Build Rust CLI and run crate tests ──
#
# The Rust CLI proof path is intentionally kept on the development feature set.
# The HMAC software-integrity lane is validated above against the release .so.
# Gate 2 deterministic verification evidence is independent of the FFI module
# software-integrity reference mechanism.
RUN cargo build -p ffi-cli --release --features "${FIPS_FEATURES_DEV}" 2>&1 && \
    cargo test  -p andna-ffi          --features "${FIPS_FEATURES_DEV}" 2>&1 && \
    cargo test  -p andna-ffi          --features "${FIPS_FEATURES_HMAC}" software_integrity -- --nocapture 2>&1 && \
    cargo test  -p andna-ffi          --features "${FIPS_FEATURES_HMAC}" hmac_integrity_lane -- --nocapture 2>&1 && \
    cargo test  -p andna-ffi          --features "${FIPS_FEATURES_HMAC}" hmac_sha256 -- --nocapture 2>&1 && \
    cargo test  -p andna-audit                                       2>&1 && \
    cargo test  -p andna-core         --features "oqs-backend"       2>&1 && \
    cargo test  -p andna-mldsa44      --features "oqs-backend"       2>&1 && \
    cargo test  -p andna-transcript                                  2>&1 && \
    cargo test  -p andna-codec                                       2>&1 && \
    cargo test  -p andna-contracts                                   2>&1

# ── Record Gate 1 artifact-bundle metadata ──
RUN sha256sum target/release/libandna_ffi.so > /build/build-hashes.txt && \
    sha256sum target/release/libandna_ffi.integrity >> /build/build-hashes.txt

# =============================================================================
# Runtime stage — slim image for CLI execution
# =============================================================================
FROM debian@sha256:74d56e3931e0d5a1dd51f8c8a2466d21de84a271cd3b5a733b803aa91abf4421 AS runtime

ENV DEBIAN_FRONTEND=noninteractive
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

RUN apt-get update -qq && apt-get install -y --no-install-recommends \
    python3 \
    python3-pip \
    && rm -rf /var/lib/apt/lists/*

# Copy artifacts from builder
COPY --from=builder /usr/local/lib/liboqs* /usr/local/lib/
COPY --from=builder /build/target/release/libandna_ffi.so /usr/local/lib/
COPY --from=builder /build/target/release/libandna_ffi.integrity /usr/local/lib/
RUN ldconfig

COPY --from=builder /build/python /opt/andna/python
WORKDIR /opt/andna/python

# Install package in editable mode for the CLI
RUN pip3 install --break-system-packages -e .

# Environment for engine selection
ENV VERIFY_ENGINE=rust
ENV ANDNA_LIB_PATH=/usr/local/lib/libandna_ffi.so
ENV LD_LIBRARY_PATH=/usr/local/lib

# Path A' HMAC software-integrity configuration.
# These paths are trusted deployment configuration for the associated integrity
# reference bundle.
ENV ANDNA_INTEGRITY_MODULE_PATH=/usr/local/lib/libandna_ffi.so
ENV ANDNA_INTEGRITY_REF_PATH=/usr/local/lib/libandna_ffi.integrity

WORKDIR /workspace

# This entrypoint will run the full test suite inside the container
ENTRYPOINT ["python3", "-m", "pytest", "-v"]