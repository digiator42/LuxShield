# LuxShield frontend image: Velo WASM console built by Trunk, served by nginx.
# Build context is the workspace root (see ../docker-compose.yml) so the
# Velo path dependency resolves inside the build.
ARG TRUNK_VERSION=0.21.14
# Backend URL baked into the WASM bundle (the page calls it directly from the
# browser). Defaults to a local backend; point it at a remote/Linux backend
# with e.g. --build-arg LUX_API_URL=http://192.168.1.50:8020
ARG LUX_API_URL=http://127.0.0.1:8020
FROM rust:1-bookworm AS builder
ARG TRUNK_VERSION
ARG LUX_API_URL
RUN rustup target add wasm32-unknown-unknown \
    && curl -sSL "https://github.com/trunk-rs/trunk/releases/download/v${TRUNK_VERSION}/trunk-x86_64-unknown-linux-gnu.tar.gz" \
        | tar -xz -C /usr/local/bin trunk
WORKDIR /src/LuxShield/frontend
# Framework first for better layer caching.
COPY Velo /src/Velo
COPY LuxShield/frontend ./
RUN sed -i 's|pub const BASE_URL: &str = "[^"]*";|pub const BASE_URL: \&str = "'"${LUX_API_URL}"'";|' src/api.rs \
    && grep -n 'pub const BASE_URL' src/api.rs \
    && trunk build --release

FROM nginx:alpine
COPY LuxShield/frontend/nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=builder /src/LuxShield/frontend/dist/ /usr/share/nginx/html/
EXPOSE 80
