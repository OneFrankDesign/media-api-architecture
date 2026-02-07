# media-api-architecture

A local-first, security-focused monorepo for a high-performance Media API architecture.

## Scope

This repository is being bootstrapped to implement a Rust + gRPC media metadata platform with Envoy gateway security controls, OPA authorization, and TypeScript SDK support.

## Architecture Intent

The system is designed around defense in depth at the gateway layer:
- strict security headers and request validation
- JWT authentication and policy authorization
- gRPC-Web to gRPC translation for web clients

## Testing Strategy (TDD-First)

This repository follows a strict test pyramid:
- unit tests: pure function and component behavior
- integration tests: service-level contracts and API semantics
- e2e tests: compose-backed cross-service behavior through real network boundaries

Hard rule for all feature work:
1. write/adjust the failing test first
2. implement the minimal change to pass
3. refactor without behavior changes

## Local Developer Workflow

Core commands:
- `pnpm test:unit`: Rust unit tests + SDK unit tests
- `pnpm test:integration`: Rust service integration tests
- `pnpm test:e2e`: compose-backed end-to-end test harness
- `pnpm test:all`: run unit + integration + e2e
- `pnpm verify`: lint + test:all + build

Suggested red/green/refactor loop:
1. run targeted test(s) and confirm failure
2. implement minimal behavior
3. run targeted test(s) until green
4. run `pnpm test:integration` for touched services
5. run `pnpm verify` before pushing

## CI Quality Gates

The following checks are required before merge to `main`:

| Check | Purpose | Risk prevented |
| --- | --- | --- |
| `ci-lint` | lint pipeline | style drift and low-signal quality regressions |
| `ci-rust` | workspace `cargo check` | compile-time breakages |
| `ci-contract` | buf lint + deterministic generation | API contract drift and generated artifact mismatch |
| `ci-security` | gitleaks + dependency audit baseline | secrets exposure and known vulnerabilities |
| `ci-compose-smoke` | compose config validation | broken local/runtime orchestration config |
| `ci-test-unit` | unit test suite | logic regressions in isolated components |
| `ci-test-integration` | service integration suite | contract/status/pagination/update-mask regressions |
| `ci-test-e2e` | compose e2e flows | cross-service and gateway enforcement regressions |

Path-filter behavior:
- `ci-test-e2e` runs for code-impacting changes.
- docs-only/config-instruction-only changes can skip e2e execution.

Branch protection policy (configure in GitHub repo settings):
- require all checks above before merge
- dismiss stale approvals when new commits are pushed
- disable force-push to `main`

## Release and Rollback

Image tagging model:
- immutable GHCR tags per commit SHA
- format: `ghcr.io/<org>/media-api-<service>:<git-sha>`

Release workflow:
- `.github/workflows/release-images.yml` builds and pushes:
  - `media-api-auth-api`
  - `media-api-main-api`
  - `media-api-gateway-envoy`
- release metadata artifact is generated via `scripts/generate-deployment-metadata.sh`

Deployment metadata contract:
- tracked template: `infra/releases/deployment-metadata.json`
- generated examples in workflows:
  - `infra/releases/deployment-metadata.generated.json`
  - `infra/releases/rollback-metadata.generated.json`

Rollback:
1. choose previous known-good SHA from metadata
2. run `bash scripts/rollback.sh <target_sha> <ghcr_owner>`
3. redeploy with rollback image tags
4. verify `/health`, `/healthz`, and Envoy `/ready`
5. mark incident outcome and update metadata

Additional runbook: `docs/runbooks/rollback.md`

## Atomic PR and Commit Rules

PR scope:
- one behavior-focused change per PR
- avoid mixed unrelated changes

Expected commit sequence:
1. test commit (failing evidence)
2. implementation commit (minimal pass)
3. optional refactor commit (no behavior change)

PR template requires:
- failing-test-first evidence
- implementation delta
- rollback reference
- risk and blast radius

## Definition of Done

A change is complete only when all conditions are met:
- required CI checks are green
- rollback steps are documented and actionable
- contract drift checks are clean (`buf` + generated artifacts)
- tests at appropriate layers are present for the behavior

## Status

Bootstrap in progress. Initial repository governance, monorepo scaffolding, infrastructure skeleton, and CI baselines are being added in staged commits.
