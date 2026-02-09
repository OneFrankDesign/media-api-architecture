# media-api-architecture

Security-first Rust monorepo for a media metadata platform behind an Envoy gateway.

## Current Stage

Phase 2 contract completion is in place:

- gateway defense-in-depth chain is active (security headers, origin/CORS checks, CSRF, JWT, OPA, gRPC-Web, router)
- ingress now strips `x-jwt-payload`; only `jwt_authn` can forward it downstream
- OPA metadata authorization requires decoded forwarded claims with non-empty `sub`
- main-api cursor tokens are HMAC signed, expiring, and verified with constant-time signature checks
- release builds now fail fast when `CURSOR_SECRET` is missing (debug builds keep a warned fallback)
- auth-api exposes `/metrics`, and Prometheus scrapes both auth-api and main-api
- metadata protobuf now includes `MetadataStatus`, `MetadataSortField`, and richer metadata fields (resolution/thumbnails/stats/custom metadata)
- sdk wrapper now uses generated protobuf request/response types (no `unknown` contract stubs)

## Services

- `services/main-api` (gRPC `MetadataService`)
  - gRPC: `50051`
  - health/metrics: `50052` (`/healthz`, `/metrics`)
  - in-memory `DashMap` store with owner/visibility indexes
- `services/auth-api` (Axum HTTP auth/session)
  - HTTP: `8081`
  - endpoints: `/health`, `/metrics`, `/auth/login`, `/auth/callback`
  - deprecated but supported: `/auth/session`, `/auth/logout` (with deprecation + sunset headers)
- `apps/gateway-envoy`
  - ingress/API gateway and security enforcement point

## Local Configuration

Start from `.env.example`.

Notable variables:

- `CORS_ALLOWED_ORIGIN_PRIMARY`
- `CORS_ALLOWED_ORIGIN_SECONDARY`
- `AUTH_CHALLENGE_SECRET` (generate with `openssl rand -hex 32`)
- `CURSOR_SECRET` (generate with `openssl rand -hex 32`)
- OIDC values (`OIDC_ISSUER`, `OIDC_CLIENT_ID`, `OIDC_AUDIENCE`, `OIDC_JWKS_URI`, etc.)

Render Envoy config (required before compose validation/up):

```bash
bash scripts/render-envoy-config.sh
```

## Development Commands

```bash
pnpm test:unit
pnpm test:integration
pnpm test:e2e
pnpm test:all
pnpm verify

pnpm compose:up
pnpm compose:down
pnpm smoke
```

## Contract and Typed SDK Workflow

Protobuf remains the source of truth:

- edit `proto/api/v1/metadata.proto` additively
- validate with:
  - `buf lint`
  - local: `buf breaking --against '.git#branch=main'`
  - CI: `buf breaking --against ".git#ref=refs/remotes/origin/${BASE_REF}"`
- regenerate SDK artifacts with:
  - `bash scripts/gen-proto.sh`

Generated TypeScript protobuf artifacts are committed under:

- `packages/sdk-ts/src/gen/**`

CI enforces deterministic generation and fails if generated artifacts drift (including untracked files).

## Health Report

Use the repo-level health command for a full local stack check and report:

```bash
pnpm health:report
# or
make health-report
```

This workflow:

- renders and validates Envoy/Compose config
- performs a full clean reset (`docker compose down --volumes --remove-orphans`)
- brings Compose up with build
- waits for container readiness
- runs `pnpm test:unit`, `pnpm test:integration`, and `pnpm test:e2e`
- runs endpoint probes and Docker diagnostics
- always tears the stack down at the end

Output artifact:

- `docs/health_report.md`

Behavior guarantees:

- report is overwritten on every run
- report is generated even on failures
- command exits non-zero when critical health steps fail

## Test Expectations

- `pnpm test:unit`: Rust unit + SDK unit tests
- `pnpm test:integration`: auth-api + main-api integration suites
- `pnpm test:e2e`: compose-backed full-stack gateway flow checks

Security-critical coverage includes:

- malformed cursor rejection and expiry handling
- cursor tamper/filter mismatch rejection
- stable cursor pagination for ASC/DESC ordering
- list filtering/sorting using metadata status and sort field semantics
- non-owner permission denial paths
- auth-api rate-limit `429` behavior
- gateway gRPC rejection for missing bearer token
- claim-aware OPA policy behavior for forwarded JWT payload

## Deferred Work

Tracked but intentionally not bundled in this hardening wave:

- exporter rollout for postgres/redis/minio/grafana scrape targets
- digest pinning for Prometheus/Grafana images
- deeper handler decomposition beyond the current list/pagination refactors
