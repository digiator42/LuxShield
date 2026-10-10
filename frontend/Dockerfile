# LuxShield frontend image: Velo WASM console built by Trunk, served by nginx.
# Build context is the workspace root (see ../docker-compose.yml) so the
# Velo path dependency resolves inside the build.
ARG TRUNK_VERSION=0.21.14
FROM rust:1-bookworm AS builder
ARG TRUNK_VERSION
RUN rustup target add wasm32-unknown-unknown \
    && curl -sSL "https://github.com/trunk-rs/trunk/releases/download/v${TRUNK_VERSION}/trunk-x86_64-unknown-linux-gnu.tar.gz" \
        | tar -xz -C /usr/local/bin trunk
WORKDIR /src/LuxShield/frontend
# Framework first for better layer caching.
COPY Velo /src/Velo
COPY LuxShield/frontend ./
RUN trunk build --release

FROM nginx:alpine
COPY LuxShield/frontend/nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=builder /src/LuxShield/frontend/dist/ /usr/share/nginx/html/
EXPOSE 80
