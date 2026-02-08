#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -lt 1 ] || [ "$#" -gt 2 ]; then
  echo "usage: $0 <target_sha> [ghcr_owner]" >&2
  exit 1
fi

target_sha="$1"
owner="${2:-${GHCR_OWNER:-${GITHUB_REPOSITORY_OWNER:-}}}"

if [ -z "$owner" ]; then
  echo "ghcr owner is required via arg, GHCR_OWNER, or GITHUB_REPOSITORY_OWNER" >&2
  exit 1
fi

if ! [[ "$target_sha" =~ ^[0-9a-f]{7,40}$ ]]; then
  echo "target_sha must be a 7-40 character lowercase hex git sha" >&2
  exit 1
fi

cat <<EOF_ROLLBACK
Rollback target SHA: ${target_sha}

1. Pull immutable images:
   docker pull ghcr.io/${owner}/media-api-auth-api:${target_sha}
   docker pull ghcr.io/${owner}/media-api-main-api:${target_sha}
   docker pull ghcr.io/${owner}/media-api-gateway-envoy:${target_sha}

2. Redeploy with your platform-specific deployment command using those image tags.

3. Verify health checks immediately after rollout:
   curl --fail --silent http://<auth-host>:8081/health
   curl --fail --silent http://<main-host>:50052/healthz
   curl --fail --silent http://<envoy-admin-host>:9901/ready

4. Record incident outcome and update infra/releases/deployment-metadata.json current/previous blocks.
EOF_ROLLBACK
