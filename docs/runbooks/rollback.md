# Rollback Runbook

## Trigger conditions

Run rollback when any of the following occur after deployment:
- required SLO/SLA regression
- repeated 5xx responses in critical paths
- auth/session failure regression
- contract incompatibility detected in downstream clients

## Inputs

- `target_sha`: previous known-good commit SHA
- GHCR owner/organization
- deployment environment

## Procedure

1. Determine rollback target from `infra/releases/deployment-metadata.json` previous block.
2. Prepare immutable images for rollback target:
   - `ghcr.io/<org>/media-api-auth-api:<target_sha>`
   - `ghcr.io/<org>/media-api-main-api:<target_sha>`
   - `ghcr.io/<org>/media-api-gateway-envoy:<target_sha>`
3. Run `bash scripts/rollback.sh <target_sha> <org>`.
4. Redeploy all services with rollback image tags using your platform command.
5. Verify health:
   - auth: `GET /health`
   - main-api: `GET /healthz`
   - envoy admin: `GET /ready`
6. Mark incident outcome and update metadata file:
   - move current -> previous
   - set current -> rollback SHA and release timestamp

## Evidence to capture

- rollback command execution logs
- post-rollback health checks
- incident ticket/status update
