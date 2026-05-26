# ── Build stage ──────────────────────────────────────────────────────────────
FROM rust:1.88-slim-bookworm AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
        pkg-config libssl-dev libclang-dev clang cmake \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

COPY . .

RUN cargo build --release --locked -p kotoba-server \
    && strip target/release/kotoba

# ── Runtime stage ─────────────────────────────────────────────────────────────
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
        libssl3 ca-certificates wget \
    && rm -rf /var/lib/apt/lists/*

RUN useradd -m -u 1000 kotoba

COPY --from=builder /build/target/release/kotoba /usr/local/bin/kotoba

RUN mkdir -p /data && chown kotoba:kotoba /data

USER kotoba

ENV KOTOBA_PORT=8080 \
    RUST_LOG=info

EXPOSE 8080
EXPOSE 4001/udp

HEALTHCHECK --interval=15s --timeout=5s --retries=3 \
    CMD wget -qO- http://localhost:8080/health || exit 1

ENTRYPOINT ["/usr/local/bin/kotoba"]
