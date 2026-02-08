FROM rust:1.93-bookworm AS chef
WORKDIR /app
RUN cargo install --locked cargo-chef

FROM chef AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

FROM chef AS cacher
COPY --from=planner /app/recipe.json recipe.json
RUN cargo chef cook --release --package auth-api --recipe-path recipe.json

FROM chef AS builder
WORKDIR /app

COPY . .
COPY --from=cacher /app/target /app/target
COPY --from=cacher /usr/local/cargo /usr/local/cargo
RUN cargo build --release -p auth-api

FROM debian:bookworm-slim
ARG VCS_REF=unknown
ARG VCS_URL=https://github.com/media-api/media-api-architecture
LABEL org.opencontainers.image.title="media-api-auth-api" \
      org.opencontainers.image.description="Media API auth service" \
      org.opencontainers.image.revision="${VCS_REF}" \
      org.opencontainers.image.source="${VCS_URL}"

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --system --gid 10001 appuser \
    && useradd --system --uid 10001 --gid appuser --create-home --home-dir /home/appuser --shell /usr/sbin/nologin appuser

COPY --from=builder --chown=appuser:appuser /app/target/release/auth-api /usr/local/bin/auth-api

EXPOSE 8081
USER appuser:appuser
CMD ["auth-api"]
