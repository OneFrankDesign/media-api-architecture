#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -lt 3 ] || [ "$#" -gt 4 ]; then
  echo "usage: $0 <current_sha> <previous_sha> <ghcr_owner> [output_path]" >&2
  exit 1
fi

current_sha="$1"
previous_sha="$2"
owner="$3"
output_path="${4:-infra/releases/deployment-metadata.json}"

if [ -z "$previous_sha" ]; then
  previous_sha="unknown"
fi

timestamp="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

mkdir -p "$(dirname "$output_path")"
cat > "$output_path" <<EOF_JSON
{
  "environment": "production",
  "current": {
    "sha": "${current_sha}",
    "released_at": "${timestamp}",
    "images": {
      "auth-api": "ghcr.io/${owner}/media-api-auth-api:${current_sha}",
      "main-api": "ghcr.io/${owner}/media-api-main-api:${current_sha}",
      "gateway-envoy": "ghcr.io/${owner}/media-api-gateway-envoy:${current_sha}"
    }
  },
  "previous": {
    "sha": "${previous_sha}",
    "released_at": "${timestamp}",
    "images": {
      "auth-api": "ghcr.io/${owner}/media-api-auth-api:${previous_sha}",
      "main-api": "ghcr.io/${owner}/media-api-main-api:${previous_sha}",
      "gateway-envoy": "ghcr.io/${owner}/media-api-gateway-envoy:${previous_sha}"
    }
  }
}
EOF_JSON

echo "deployment metadata written to ${output_path}"
