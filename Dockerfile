# =============================================================================
# AN-DNA vNext Phase 1 — Deterministic Docker Build
# Gate 1 acceptance: identical output across any Linux host.
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
ARG RUST_VERSION=1.76.0
ARG LIBOQS_VERSION=0.10.1

# ── System build dependencies (Fixed: Added libclang/llvm for bindgen) ──
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

# Force bindgen to find the installed libclang
ENV LIBCLANG_PATH=/usr/lib/llvm-14/lib
ENV LD_LIBRARY_PATH=/usr/local/lib

RUN cargo build --release --all 2>&1 && \
    cargo test --all 2>&1

# ── Record build metadata ──
RUN sha256sum target/release/libandna_ffi.so > /build/build-hashes.txt

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
RUN ldconfig

COPY --from=builder /build/python /opt/andna/python
WORKDIR /opt/andna/python

# Install package in editable mode for the CLI
RUN pip3 install --break-system-packages -e .

# Environment for engine selection
ENV VERIFY_ENGINE=rust
ENV ANDNA_LIB_PATH=/usr/local/lib/libandna_ffi.so
ENV LD_LIBRARY_PATH=/usr/local/lib

WORKDIR /workspace
# This entrypoint will run the full test suite inside the container
ENTRYPOINT ["python3", "-m", "pytest", "-v"]