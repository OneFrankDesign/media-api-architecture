# Phase 3 ABAC/NGAC Policy Foundation Spec

## Status

- Phase: `phase3`
- Branch target: `phase3/abac-policy-foundation`
- Scope: Introduce ABAC/NGAC policy surface while preserving gateway-centric enforcement

## Goals

1. Add an ABAC policy module (`policies/abac.rego`) with metadata-service method decisions.
2. Introduce attribute-aware authorization conditions beyond role-only checks.
3. Keep current defense-in-depth order unchanged (Envoy JWT -> OPA ext_authz -> service checks).
4. Keep default-deny behavior for unknown/malformed/attribute-missing requests.

## Non-goals

1. No removal of existing RBAC policy in this kickoff step.
2. No changes to Envoy filter ordering or bypass routes.
3. No changes to main-api application-layer owner/admin checks.

## Policy Model (Phase 3 Foundation)

ABAC decision inputs should support:

1. Subject attributes:
   - `sub`
   - `roles`
   - additional claims (`org`, `project`, `clearance`, etc.)
2. Resource attributes:
   - `owner_id`
   - `status`
   - `visibility`
   - custom metadata tags
3. Action/method attributes:
   - gRPC method name
   - request intent (`read`, `write`, `delete`)
4. Environment attributes:
   - request origin/path/method metadata from ext_authz input

NGAC-style grouping target:

- represent subject/resource attributes as policy-addressable sets
- allow reusable relationship predicates (e.g., same project/org)

## Initial Authorization Expectations

1. `Health` remains allowed.
2. Authenticated users with valid non-empty `sub` can create metadata.
3. Owners can get/list/update/delete their own metadata.
4. Non-owners are denied unless elevated policy attributes are present.
5. Admin role remains privileged and can cross owner boundaries.
6. Deny when forwarded claims are malformed, missing, or missing `sub`.

## TDD Plan

Commit sequence for this kickoff:

1. spec commit (this document)
2. failing Rego tests (`policies/tests/abac_test.rego`)
3. implementation (`policies/abac.rego`) to satisfy tests

## Acceptance Tests

Policy tests must cover:

1. owner access allowed for metadata read/update
2. admin access allowed cross-owner
3. create allowed for authenticated identity
4. deny on missing `sub`
5. deny for non-owner non-admin without additional attributes
6. malformed forwarded claim payload denied

## Validation Commands

Policy-only validation command for development:

```bash
docker run --rm -v "$PWD":/workspace -w /workspace openpolicyagent/opa:0.67.1 \
  test policies/abac.rego policies/tests/abac_test.rego
```

Repository baseline gates remain required before merge:

1. `cargo fmt --all --check`
2. `cargo clippy --workspace --all-targets -- -D warnings`
3. `cargo check --workspace`
4. `buf lint`
5. `buf breaking --against ".git#ref=refs/remotes/origin/main"`

## Rollout Constraints

1. Keep existing RBAC enforcement active until ABAC parity is proven.
2. Add ABAC in additive mode first; avoid policy cut-over in the same change.
3. Preserve deny-by-default posture throughout rollout.
