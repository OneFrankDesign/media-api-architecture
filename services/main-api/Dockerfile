FROM rust:1.84-bookworm AS builder
WORKDIR /app

COPY . .
RUN cargo build --release -p main-api

FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/target/release/main-api /usr/local/bin/main-api

EXPOSE 50051 50052
CMD ["main-api"]
