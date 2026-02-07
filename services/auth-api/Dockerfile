FROM rust:1.84-bookworm AS builder
WORKDIR /app

COPY . .
RUN cargo build --release -p auth-api

FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/target/release/auth-api /usr/local/bin/auth-api

EXPOSE 8081
CMD ["auth-api"]
