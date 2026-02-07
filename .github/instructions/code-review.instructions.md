---
applyTo: "**"
---

# Media API Code Review Instructions

Use this file when reviewing pull requests in this repository.

## 1. Repository Technology Inventory (Current)

- Monorepo tooling: `pnpm` workspaces, `turbo`, `Makefile`
- Languages: Rust 2021 (`services/*`), TypeScript (`packages/sdk-ts`), Rego (`policies`), Protobuf (`proto`), Lua (inline Envoy filters), Shell/Bash (`scripts/*`), YAML configs
- Backend runtime/frameworks: `tokio`, `axum`, `tonic` (gRPC), `tracing`, `serde`, `uuid`, `anyhow`
- API contracts/codegen: `proto3`, `buf` (`buf lint`, breaking checks), `tonic-build`, `protoc-bin-vendored`, Buf ES plugin for TS
- Gateway/security: Envoy (`jwt_authn`, `ext_authz`, `grpc_web`, Lua filters)
- Authorization policy: Open Policy Agent (OPA) + Rego tests
- Infra/runtime: Dockerfiles, Docker Compose
- Data/infra dependencies: PostgreSQL, Redis, MinIO
- Observability: Prometheus, Grafana, service health endpoints
- CI/security checks: GitHub Actions, Gitleaks, npm audit baseline, compose config smoke, contract generation drift check

## 2. Global Review Priorities

Prioritize findings in this order:

1. Security vulnerabilities and authz/authn bypasses
2. Contract compatibility and data correctness regressions
3. Runtime reliability (crashes, deadlocks, bad shutdown, resource leaks)
4. Performance/scalability regressions
5. Maintainability and test coverage gaps

Do not spend review budget on minor style nits unless they hide a defect.

## 3. Best Practices and Pitfalls by Technology

### Rust + Tokio + Axum + Tonic

Best practices:
- Preserve non-blocking async behavior; avoid CPU-heavy/blocking work on async tasks.
- Validate all external input and return precise status/error types.
- Keep graceful shutdown and task join behavior deterministic.
- Keep health endpoints cheap and independent of heavy dependencies.
- Prefer explicit error propagation over panics/`unwrap`.

Pitfalls to flag:
- Blocking calls in async handlers.
- Missing validation for IDs, pagination, update masks, or enum fields.
- Inconsistent HTTP/gRPC status semantics.
- Unbounded in-memory growth and expensive cloning in hot paths.
- Silent error swallowing during shutdown.

### Protobuf + Buf + Code Generation

Best practices:
- Maintain backward wire compatibility: never reuse field numbers.
- Prefer additive contract changes over breaking changes.
- Keep generated code deterministic (`scripts/gen-proto.sh` must produce no diffs after commit).
- Ensure server implementation behavior matches proto comments/fields.

Pitfalls to flag:
- Renaming/removing fields without `reserved` strategy.
- Breaking request/response semantics without migration plan.
- Manual edits inside generated output directories.
- Contract changes without corresponding service and SDK updates.

### TypeScript SDK (`packages/sdk-ts`)

Best practices:
- Keep request/response types specific (avoid `unknown` where real types exist).
- Keep auth metadata headers consistent and centralized.
- Preserve compatibility with generated clients and transport expectations.

Pitfalls to flag:
- Weak typing that hides runtime breakages.
- Header names/casing drifting from gateway expectations.
- Mixing generated and hand-written responsibilities.

### Envoy Gateway + Lua + JWT + ext_authz

Best practices:
- Preserve secure filter ordering and deny-by-default behavior.
- Keep auth bypasses narrow (`/health`, `/auth` only where intended).
- Validate CORS/CSRF/origin logic with explicit allowlists.
- Ensure external auth inputs are canonical and not client-spoofable.

Pitfalls to flag:
- Route precedence changes that accidentally bypass auth.
- Relaxed origin/CSRF checks or wildcard trust.
- Excessive dependence on Lua where native filters are safer/clearer.
- JWT config drift (issuer, audience, JWKS cluster mismatch).

### OPA/Rego Policies

Best practices:
- Keep `default deny` posture.
- Add/maintain policy tests for allow and deny paths.
- Keep policy input schema expectations explicit.

Pitfalls to flag:
- Allow rules that become overly broad due to missing guards.
- Policy/test drift.
- Implicit assumptions about absent fields.

### Docker/Compose + Service Dependencies

Best practices:
- Pin base images and runtime versions where practical.
- Keep health checks meaningful and fast.
- Keep secrets out of source; use env indirection.
- Prefer least-privilege container runtime settings.

Pitfalls to flag:
- `latest` tags in critical components without rationale.
- Default credentials in non-local contexts.
- Missing dependency health gating.
- Inconsistent exposed ports or unsafe network assumptions.

### CI/CD (GitHub Actions)

Best practices:
- Keep checks deterministic and fail on real regressions.
- Validate generated artifacts are committed when required.
- Ensure security checks are actionable and not permanently non-blocking.

Pitfalls to flag:
- CI steps that pass while skipping important verification.
- Overuse of `continue-on-error` for security gates.
- Missing tests for touched high-risk paths.

### Shell Scripts (`scripts/*`)

Best practices:
- Start every script with `set -euo pipefail`.
- Quote all variable expansions to prevent word splitting.
- Check for required tools with `command -v` before use.
- Use relative paths from repo root; avoid hardcoded absolute paths.

Pitfalls to flag:
- Unquoted variables or glob expansions.
- Missing error handling or silent failures.
- Undeclared external dependencies (e.g., `buf`, `protoc`).
- Bash-specific syntax without a `#!/usr/bin/env bash` shebang.

### PostgreSQL (`infra/migrations/*`)

Best practices:
- Write idempotent, reversible migrations (up + down).
- Add indexes concurrently (`CREATE INDEX CONCURRENTLY`) to avoid table locks.
- Use parameterized queries exclusively; never interpolate user input into SQL.
- Review DDL for lock implications on high-traffic tables.

Pitfalls to flag:
- Destructive DDL (`DROP TABLE`, `DROP COLUMN`) without a rollback plan.
- Missing indexes on foreign key columns or frequent query predicates.
- Unbounded `SELECT` without `LIMIT` or pagination.
- Storing secrets or PII in plaintext rows.

### Redis

Best practices:
- Set TTLs on all cache keys; no indefinite keys without justification.
- Use consistent serialization formats (JSON or protobuf, not mixed).
- Namespace keys by service or domain (e.g., `media:meta:<id>`).
- Bound memory usage with `maxmemory` and eviction policies.

Pitfalls to flag:
- Missing TTLs leading to unbounded memory growth.
- Key naming collisions across services.
- Storing large values (>1 MB) that block the Redis event loop.
- Using Redis as a primary data store without persistence guarantees.

### MinIO / Object Storage

Best practices:
- Use presigned URLs with short expiry for client uploads/downloads.
- Keep buckets private by default; no public ACLs without explicit review.
- Validate MIME types and enforce upload size limits before accepting files.

Pitfalls to flag:
- Public bucket policies or overly permissive ACLs.
- Missing or excessively long expiry on presigned URLs.
- Unbounded upload sizes without server-side limits.
- Accepting user content without content-type validation.

### Monitoring Configs (`infra/monitoring/*`)

Best practices:
- Ensure scrape targets match actual service endpoints (ports, paths).
- Use consistent label naming across all targets.
- Set alert thresholds based on SLOs, not arbitrary values.

Pitfalls to flag:
- Scrape targets pointing to non-existent or renamed endpoints.
- Missing scrape targets for newly added services.
- Overly aggressive scrape intervals that increase load.
- Sensitive data leaking into metric labels.

## 4. Area-Specific Review Playbooks

### A) `services/main-api/**` (gRPC metadata service)

Review for:
- CRUD correctness against proto contract.
- Pagination correctness (`page_size`, `page_token`, stable sort guarantees).
- Partial update semantics (`FieldMask` handling, unsupported fields, validation).
- Concurrency safety and memory growth of in-memory store.
- gRPC status code correctness (`invalid_argument`, `not_found`, etc.).

### B) `services/auth-api/**` (session + CSRF service)

Review for:
- Cookie safety (`HttpOnly`, `Secure`, `SameSite`, domain handling).
- Logout invalidation correctness.
- CSRF token issuance/verification contract with gateway.
- No sensitive data leakage in responses/logs.

### C) `apps/gateway-envoy/**` (edge security)

Review for:
- Filter order and route matching precedence.
- JWT enforcement scope and exceptions.
- OPA ext_authz request shaping and timeout behavior.
- CSRF/origin protections for non-idempotent methods.
- Security header integrity.

### D) `policies/**` (authorization)

Review for:
- Principle of least privilege.
- Correct role/action/resource evaluation.
- Test coverage for both positive and negative cases.

### E) `proto/**`, `buf*.yaml`, `scripts/gen-proto.sh`, `packages/sdk-ts/src/gen/**`

Review for:
- Contract compatibility and lint adherence.
- Deterministic generation and drift.
- Alignment between proto changes and SDK/service behavior.

### F) `infra/**`, `services/**/Dockerfile`, `infra/compose/**`, `infra/migrations/**`

Review for:
- Secure defaults for local-first infra.
- Correct health checks and startup dependencies.
- No accidental production-hostile defaults.
- Migration reversibility and lock safety (when migrations are added).

### G) `.github/workflows/**`

Review for:
- Complete coverage for changed risk areas.
- Deterministic install/build/test behavior.
- Security checks that are meaningful and enforced.

### H) `infra/monitoring/**` (observability config)

Review for:
- Scrape target correctness (ports, paths match actual service endpoints).
- Label consistency across all targets.
- No sensitive data in metric labels or alert annotations.
- New services are added as scrape targets when introduced.

## 5. Required Review Output Format

For each finding, provide:

1. Severity: `high`, `medium`, or `low`
2. Location: exact file path and line(s)
3. Why it matters: concrete risk/regression
4. Suggested fix: minimal patch-level recommendation
5. Confidence: `high`, `medium`, or `low`

If no issues are found, explicitly state:
- what was reviewed
- why the change appears safe
- what tests/checks are still missing (if any)

## 6. Scope and Exclusions

- Treat generated files as derived artifacts; review source contracts and generation config first.
- Do not request broad rewrites in bootstrap files unless there is a correctness or security defect.
- Prefer small, verifiable changes aligned with existing architecture intent in `README.md`.
