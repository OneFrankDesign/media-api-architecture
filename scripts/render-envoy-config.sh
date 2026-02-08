#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

ENV_FILE="${1:-.env.example}"
if [[ ! -f "$ENV_FILE" ]]; then
  echo "env file not found: $ENV_FILE" >&2
  exit 1
fi
set -a
source "$ENV_FILE"
set +a

: "${OIDC_ISSUER:?OIDC_ISSUER is required}"
: "${OIDC_CLIENT_ID:?OIDC_CLIENT_ID is required}"
: "${OIDC_AUDIENCE:?OIDC_AUDIENCE is required}"
: "${OIDC_JWKS_URI:?OIDC_JWKS_URI is required}"
: "${OIDC_JWKS_HOST:?OIDC_JWKS_HOST is required}"
: "${OIDC_JWKS_PORT:?OIDC_JWKS_PORT is required}"
: "${CORS_ALLOWED_ORIGIN_PRIMARY:?CORS_ALLOWED_ORIGIN_PRIMARY is required}"
: "${CORS_ALLOWED_ORIGIN_SECONDARY:?CORS_ALLOWED_ORIGIN_SECONDARY is required}"

envsubst '${OIDC_ISSUER} ${OIDC_CLIENT_ID} ${OIDC_AUDIENCE} ${OIDC_JWKS_URI} ${OIDC_JWKS_HOST} ${OIDC_JWKS_PORT} ${CORS_ALLOWED_ORIGIN_PRIMARY} ${CORS_ALLOWED_ORIGIN_SECONDARY}' \
  < apps/gateway-envoy/envoy.yaml.tpl \
  > apps/gateway-envoy/envoy.yaml
