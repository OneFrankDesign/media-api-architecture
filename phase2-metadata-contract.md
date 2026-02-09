# Phase 2 Metadata Contract Completion Spec

## Status

- Phase: `phase2`
- Branch target: `phase2/complete-metadata-contract-and-typed-sdk`
- Contract source of truth: `proto/api/v1/metadata.proto`

## Goals

1. Complete Phase 2 metadata protobuf contract with additive-only schema changes.
2. Enforce cursor integrity and deterministic pagination under filter/sort changes.
3. Remove SDK `unknown` request/response types in favor of generated protobuf types.
4. Preserve all existing gateway-first security and hardening assumptions.

## Non-goals

1. No gateway security model changes.
2. No breaking protobuf changes.
3. No ABAC/NGAC policy rollout in this phase (Phase 3 only).

## Protobuf Additions (Additive Only)

### New Enums

```proto
enum MetadataStatus {
  METADATA_STATUS_UNSPECIFIED = 0;
  METADATA_STATUS_PROCESSING = 1;
  METADATA_STATUS_READY = 2;
  METADATA_STATUS_FAILED = 3;
  METADATA_STATUS_ARCHIVED = 4;
}

enum MetadataSortField {
  METADATA_SORT_FIELD_UNSPECIFIED = 0;
  METADATA_SORT_FIELD_CREATED_AT = 1;
  METADATA_SORT_FIELD_UPDATED_AT = 2;
  METADATA_SORT_FIELD_TITLE = 3;
  METADATA_SORT_FIELD_FILE_SIZE = 4;
}
```

### New Messages

```proto
message VideoResolution {
  uint32 width = 1;
  uint32 height = 2;
}

message Thumbnail {
  string uri = 1;
  uint32 width = 2;
  uint32 height = 3;
}

message VideoStats {
  uint64 view_count = 1;
  uint64 like_count = 2;
  uint64 comment_count = 3;
}
```

### Existing Message Expansion

`VideoMetadata` new fields:

- `status = 12` (`MetadataStatus`)
- `resolution = 13` (`VideoResolution`)
- `thumbnails = 14` (`repeated Thumbnail`)
- `stats = 15` (`VideoStats`)
- `custom_metadata = 16` (`map<string, string>`)

`ListMetadataRequest` new fields:

- `filter_status = 8` (`MetadataStatus`)
- `sort_field = 9` (`MetadataSortField`)

### Cursor Semantics Comments (Proto)

`ListMetadataRequest.page_token` comment:

- Opaque token from `next_page_token`.
- Caller must keep filter/sort parameters consistent between pages.
- Mismatch or tamper returns `INVALID_ARGUMENT`.

`ListMetadataResponse.next_page_token` comment:

- Opaque signed cursor; empty means no further page.

## Behavioral Contract

1. Default list sort when unspecified:
   - `sort_field = CREATED_AT`
   - `sort_direction = ASC`
2. Stable ordering for all sort modes:
   - Primary sort by selected field
   - Deterministic tie-break by `id`
3. Cursor validation:
   - Signature verified in constant time
   - Cursor filter hash must match request filters
   - Cursor sort direction and sort field must match request
4. Filter behavior:
   - `filter_status` applies exact status matching when non-zero
5. Metadata defaults on create:
   - `status = READY`
   - `resolution`, `thumbnails`, `stats`, and `custom_metadata` copied from request when present
6. Update behavior:
   - New fields are patchable via `update_mask`
   - Unsupported mask paths return `INVALID_ARGUMENT`

## Compatibility Rules

1. Additive-only protobuf changes.
2. No field renumbering, reuse, or removal.
3. Existing enum numeric values remain stable.
4. Existing request/response field behavior remains backward compatible.
5. Buf lint + Buf breaking are required gates.
   - local baseline command: `buf breaking --against '.git#branch=main'`
   - CI baseline command: `buf breaking --against ".git#ref=refs/remotes/origin/${BASE_REF}"`

## Acceptance Tests

### Integration (`services/main-api/tests/main_api_integration.rs`)

1. Cursor tamper rejection returns `INVALID_ARGUMENT`.
2. Cursor with changed filters returns `INVALID_ARGUMENT`.
3. Pagination remains stable for equal timestamps in both ASC and DESC.
4. Expanded metadata fields (`status`, `resolution`, `thumbnails`, `stats`, `custom_metadata`) round-trip through create/get/list/update.
5. `filter_status` and `sort_field` are enforced by list behavior.

### E2E (`tests/e2e-harness/tests/gateway_e2e.rs`)

1. Gateway paginated list supports new list request fields and still returns valid cursor pages.
2. Gateway rejects mismatched cursor/filter combinations with `INVALID_ARGUMENT`.
3. Existing JWT + OPA + CSRF + origin protections remain enforced.

### SDK (`packages/sdk-ts`)

1. Generated types under `packages/sdk-ts/src/gen/**` are committed.
2. `MediaApiSdk` uses generated request/response types (no `unknown`).
3. SDK unit tests assert typed method delegation and metadata header behavior.

## Phase Exit Gates

1. `cargo fmt --all --check`
2. `cargo clippy --workspace --all-targets -- -D warnings`
3. `cargo check --workspace`
4. `cargo test -p auth-api --test auth_api_integration`
5. `cargo test -p main-api --test main_api_integration`
6. `cargo test -p e2e-harness --test gateway_e2e -- --nocapture`
7. `buf lint`
8. `buf breaking --against '.git#branch=main'` (local) or `buf breaking --against ".git#ref=refs/remotes/origin/${BASE_REF}"` (CI)
9. `bash scripts/gen-proto.sh`
10. `pnpm health:report`

## Documentation Update Rule

Update `.codex/ARCHITECTURE.md` phase status to Phase 2 complete only after all Phase Exit Gates pass.
