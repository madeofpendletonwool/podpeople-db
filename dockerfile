# Build
FROM rust:1.99-alpine AS builder
RUN apk add --no-cache musl-dev
WORKDIR /app
COPY Cargo.toml Cargo.lock ./
# Cache dependencies separately from the app source.
RUN mkdir src && echo 'fn main() {}' > src/main.rs && echo '' > src/lib.rs \
    && cargo build --release --locked 2>/dev/null || true
COPY migrations ./migrations
COPY templates ./templates
COPY static ./static
COPY src ./src
RUN touch src/main.rs src/lib.rs && cargo build --release --locked

# Run
FROM alpine:3.22
RUN apk add --no-cache ca-certificates tzdata && mkdir -p /app/podpeople-data
WORKDIR /app
COPY --from=builder /app/target/release/podpeople /usr/local/bin/podpeople
# Runs as root like v1 did, so existing (root-owned) data volumes keep working on upgrade.
ENV PORT=8085 DB_PATH=/app/podpeople-data/podpeople-v2.sqlite
EXPOSE 8085
VOLUME /app/podpeople-data
HEALTHCHECK --interval=30s --timeout=5s CMD wget -qO- http://127.0.0.1:8085/api/v2/stats >/dev/null || exit 1
CMD ["podpeople"]
