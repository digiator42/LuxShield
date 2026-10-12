# syntax=docker/dockerfile:1.7
#
# LuxShield backend image: GritShield manager (crates.io) + the aya-bpf XDP
# probe object. The probe is built for `bpfel-unknown-none` (nightly +
# build-std + bpf-linker); the manager links the aya ring-buffer pump
# (`--features ebpf`). Runtime ring source is chosen by $LUX_RING:
#
#   sim  -> portable simulator (no kernel, no privileges)   [default]
#   ebpf -> attach the probe to a NIC (needs privileged + host network +
#           /sys/kernel/btf/vmlinux; see docker-compose.ebpf.yml)
#
# Build context is the LuxShield repo root (see docker-compose.yml).

# -------- Stage 1: build the eBPF probe (nightly + bpf-linker) ---------
FROM rust:1-bookworm AS probe
RUN apt-get update \
 && apt-get install -y --no-install-recommends curl zstd \
 && rm -rf /var/lib/apt/lists/*
# bpf-linker from the official prebuilt releases (do NOT build it from source)
RUN curl -sL https://github.com/aya-rs/bpf-linker/releases/latest/download/bpf-linker-x86_64-unknown-linux-musl.tar.zst -o /tmp/bpl.tar.zst \
 && tar --zstd -xf /tmp/bpl.tar.zst -C /usr/local/bin \
 && rm /tmp/bpl.tar.zst \
 && bpf-linker --version
RUN rustup toolchain install nightly --profile minimal \
 && rustup component add rust-src --toolchain nightly
ENV CARGO_TARGET_DIR=/cargo-target
WORKDIR /src/xdp-probe
COPY lux-common/ /src/lux-common/
COPY xdp-probe/ /src/xdp-probe/
RUN --mount=type=cache,target=/cargo-target \
    --mount=type=cache,target=/usr/local/cargo/registry \
    mkdir -p /out \
 && cargo +nightly build --release \
 && cp /cargo-target/bpfel-unknown-none/release/xdp-probe /out/xdp-probe.o

# -------- Stage 2: build the GritShield manager (with the aya bridge) --
FROM rust:1-bookworm AS builder
RUN apt-get update \
 && apt-get install -y --no-install-recommends pkg-config libssl-dev \
 && rm -rf /var/lib/apt/lists/*
ENV CARGO_TARGET_DIR=/cargo-target
WORKDIR /src
COPY Cargo.toml ./Cargo.toml
COPY Cargo.lock ./Cargo.lock
COPY backend ./backend
COPY lux-common ./lux-common
RUN --mount=type=cache,target=/cargo-target \
    --mount=type=cache,target=/usr/local/cargo/registry \
    mkdir -p /out \
 && cargo build -p luxshield-backend --release --features ebpf \
 && cp /cargo-target/release/luxshield-backend /out/luxshield-backend

# -------- Stage 3: runtime ---------------------------------------------
FROM debian:bookworm-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl \
 && rm -rf /var/lib/apt/lists/*
COPY --from=builder /out/luxshield-backend /usr/local/bin/luxshield-backend
COPY --from=probe /out/xdp-probe.o /opt/luxshield/xdp-probe.o
ENV LUX_BIND=0.0.0.0 \
    LUX_PORT=8020 \
    LUX_RING=sim \
    LUX_XDP_OBJ=/opt/luxshield/xdp-probe.o \
    LUX_XDP_IFACE=eth0
HEALTHCHECK CMD curl -fsS http://127.0.0.1:8020/health || exit 1
EXPOSE 8020
CMD ["luxshield-backend"]
