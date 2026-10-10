# LuxShield backend image (GritShield manager + sim/XDP packet pump).
# Build context is the workspace root (see ../docker-compose.yml).
# GritShield comes from crates.io 0.3.1 (see backend/Cargo.toml), so no repo
# copy is needed.
FROM rust:1-bookworm AS builder
WORKDIR /src/LuxShield
COPY LuxShield/Cargo.toml ./Cargo.toml
COPY LuxShield/Cargo.lock ./Cargo.lock
COPY LuxShield/backend ./backend
COPY LuxShield/lux-common ./lux-common
# Default features (mcp + sim). The live XDP pump needs --features ebpf on a
# privileged Linux host with BPF maps mounted; sim is the portable default.
RUN cargo build --release

FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=builder /src/LuxShield/target/release/luxshield-backend /usr/local/bin/luxshield-backend
ENV LUX_BIND=0.0.0.0 \
    LUX_PORT=8020
EXPOSE 8020
CMD ["luxshield-backend"]
