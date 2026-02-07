#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

if ! command -v buf >/dev/null 2>&1; then
  echo "buf is required. Install from https://buf.build/docs/installation" >&2
  exit 1
fi

rm -rf packages/sdk-ts/src/gen services/main-api/src/gen
mkdir -p packages/sdk-ts/src/gen services/main-api/src/gen

buf generate --template buf.gen.yaml

echo "proto generation complete"
