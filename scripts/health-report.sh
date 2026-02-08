#!/usr/bin/env bash
set -euo pipefail

COMPOSE_FILE="infra/compose/docker-compose.yml"
ENV_FILE=".env.example"
REPORT_PATH="docs/health_report.md"
SCRIPT_VERSION="v1"
WAIT_SECS="${HEALTH_REPORT_WAIT_SECS:-180}"
POLL_SECS="${HEALTH_REPORT_POLL_SECS:-2}"

OVERALL_FAIL=0
FINALIZED=0
SUMMARY_ROWS=""
READINESS_ROWS=""
PROBE_ROWS=""
FAILED_STEPS=""

start_epoch="$(date +%s)"
generated_utc="$(date -u '+%Y-%m-%d %H:%M:%S UTC')"
generated_local="$(date '+%Y-%m-%d %H:%M:%S %Z')"
branch="$(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo unknown)"
commit="$(git rev-parse --short HEAD 2>/dev/null || echo unknown)"
host_name="$(hostname 2>/dev/null || echo unknown)"
repo_path="$(pwd)"

log_line() {
  printf '%s\n' "$*" >> "$REPORT_PATH"
}

add_failed_step() {
  local step="$1"
  if [[ -z "$FAILED_STEPS" ]]; then
    FAILED_STEPS="$step"
  else
    FAILED_STEPS="$FAILED_STEPS, $step"
  fi
}

record_summary() {
  local step="$1"
  local status="$2"
  local duration="$3"
  SUMMARY_ROWS="${SUMMARY_ROWS}| ${step} | ${status} | ${duration}s |\n"
}

run_command_step() {
  local step="$1"
  local command="$2"
  local critical="${3:-1}"

  local step_start
  step_start="$(date +%s)"

  log_line ""
  log_line "## ${step}"
  log_line ""
  log_line '```bash'
  log_line "$command"
  log_line '```'
  log_line ""

  set +e
  local output
  output="$(bash -c "$command" 2>&1)"
  local exit_code=$?
  set -e

  local step_end
  step_end="$(date +%s)"
  local duration=$((step_end - step_start))
  local status="PASS"
  if [[ "$exit_code" -ne 0 ]]; then
    status="FAIL"
  fi

  log_line "**Exit Code:** ${exit_code}"
  log_line ""
  log_line "**Duration:** ${duration}s"
  log_line ""
  log_line '```text'
  if [[ -n "$output" ]]; then
    log_line "$output"
  else
    log_line "<no output>"
  fi
  log_line '```'

  record_summary "$step" "$status" "$duration"

  if [[ "$exit_code" -ne 0 && "$critical" -eq 1 ]]; then
    OVERALL_FAIL=1
    add_failed_step "$step"
  fi

  return "$exit_code"
}

skip_step() {
  local step="$1"
  local reason="$2"
  log_line ""
  log_line "## ${step}"
  log_line ""
  log_line "_SKIPPED: ${reason}_"
  record_summary "$step" "SKIP" "0"
}

append_report_header() {
  mkdir -p "$(dirname "$REPORT_PATH")"
  : > "$REPORT_PATH"

  log_line "# Media API Health Report"
  log_line ""
  log_line "Generated (UTC): ${generated_utc}  "
  log_line "Generated (Local): ${generated_local}  "
  log_line "Host: ${host_name}  "
  log_line "Repo: ${repo_path}  "
  log_line "Branch: ${branch}  "
  log_line "Commit: ${commit}  "
  log_line "Command: \`pnpm health:report\`  "
  log_line "Script Version: ${SCRIPT_VERSION}"
  log_line ""
}

run_preflight() {
  run_command_step "Preflight" "command -v bash && command -v docker && command -v pnpm && command -v curl && command -v jq && command -v envsubst" 1
}

run_compose_render_and_validate() {
  run_command_step "Compose Render and Validate" "bash scripts/render-envoy-config.sh && docker compose -f ${COMPOSE_FILE} --env-file ${ENV_FILE} config >/dev/null" 1
}

run_clean_down() {
  run_command_step "Compose Down (full clean)" "docker compose -f ${COMPOSE_FILE} --env-file ${ENV_FILE} down --volumes --remove-orphans" 1
}

run_compose_up() {
  run_command_step "Compose Up (build)" "docker compose -f ${COMPOSE_FILE} --env-file ${ENV_FILE} up -d --build" 1
}

wait_for_service() {
  local service="$1"
  local start
  start="$(date +%s)"
  local last_state="unknown"
  local last_health="unknown"
  local last_restarts="-"
  local container_id=""

  while true; do
    set +e
    container_id="$(docker compose -f "${COMPOSE_FILE}" --env-file "${ENV_FILE}" ps -q "${service}" 2>/dev/null)"
    local ps_exit=$?
    set -e

    if [[ "${ps_exit}" -ne 0 ]]; then
      local now
      now="$(date +%s)"
      local elapsed=$((now - start))
      READINESS_ROWS="${READINESS_ROWS}| ${service} | - | docker-error | n/a | - | ${elapsed}s | FAIL |\n"
      return 1
    fi

    if [[ -n "${container_id}" ]]; then
      local inspect
      inspect="$(docker inspect -f '{{.State.Status}}|{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}|{{.RestartCount}}' "${container_id}" 2>/dev/null || true)"
      if [[ -n "${inspect}" ]]; then
        last_state="$(printf '%s' "${inspect}" | awk -F'|' '{print $1}')"
        last_health="$(printf '%s' "${inspect}" | awk -F'|' '{print $2}')"
        last_restarts="$(printf '%s' "${inspect}" | awk -F'|' '{print $3}')"
      fi

      if [[ "${last_state}" == "running" ]]; then
        if [[ "${last_health}" == "none" || "${last_health}" == "healthy" ]]; then
          local end
          end="$(date +%s)"
          local elapsed=$((end - start))
          local short_id="${container_id:0:12}"
          READINESS_ROWS="${READINESS_ROWS}| ${service} | ${short_id} | ${last_state} | ${last_health} | ${last_restarts} | ${elapsed}s | PASS |\n"
          return 0
        fi
      fi
    fi

    local now
    now="$(date +%s)"
    local elapsed=$((now - start))
    if [[ "${elapsed}" -ge "${WAIT_SECS}" ]]; then
      local short_id="-"
      if [[ -n "${container_id}" ]]; then
        short_id="${container_id:0:12}"
      fi
      READINESS_ROWS="${READINESS_ROWS}| ${service} | ${short_id} | ${last_state} | ${last_health} | ${last_restarts} | ${elapsed}s | FAIL |\n"
      return 1
    fi

    sleep "${POLL_SECS}"
  done
}

run_readiness_checks() {
  local readiness_start
  readiness_start="$(date +%s)"

  log_line ""
  log_line "## Service Readiness"
  log_line ""

  local phase_fail=0
  local services
  services="$(docker compose -f "${COMPOSE_FILE}" --env-file "${ENV_FILE}" config --services)"
  while IFS= read -r service; do
    [[ -z "${service}" ]] && continue
    if ! wait_for_service "${service}"; then
      phase_fail=1
    fi
  done <<< "${services}"

  log_line "| Service | Container | State | Health | Restarts | Ready In | Status |"
  log_line "| --- | --- | --- | --- | --- | --- | --- |"
  if [[ -n "${READINESS_ROWS}" ]]; then
    printf '%b' "${READINESS_ROWS}" >> "${REPORT_PATH}"
  else
    log_line "| <none> | - | - | - | - | - | FAIL |"
    phase_fail=1
  fi

  local readiness_end
  readiness_end="$(date +%s)"
  local duration=$((readiness_end - readiness_start))

  if [[ "${phase_fail}" -eq 0 ]]; then
    record_summary "Service Readiness" "PASS" "${duration}"
  else
    record_summary "Service Readiness" "FAIL" "${duration}"
    OVERALL_FAIL=1
    add_failed_step "Service Readiness"
  fi
}

run_test_suites() {
  run_command_step "Unit Tests" "pnpm test:unit" 1 || true
  run_command_step "Integration Tests" "pnpm test:integration" 1 || true
  run_command_step "E2E Tests" "pnpm test:e2e" 1 || true
}

probe_endpoint() {
  local name="$1"
  local url="$2"
  local expected="$3"

  local probe_start
  probe_start="$(date +%s)"

  local body_file
  body_file="$(mktemp)"

  set +e
  local response_code
  response_code="$(curl -sS -o "${body_file}" -w '%{http_code}' "${url}")"
  local curl_exit=$?
  local body
  body="$(cat "${body_file}" 2>/dev/null || true)"
  rm -f "${body_file}"
  set -e

  local probe_end
  probe_end="$(date +%s)"
  local duration=$((probe_end - probe_start))
  local status="PASS"
  if [[ "${curl_exit}" -ne 0 || "${response_code}" != "${expected}" ]]; then
    status="FAIL"
  fi

  PROBE_ROWS="${PROBE_ROWS}| ${name} | \`${url}\` | ${expected} | ${response_code:-n/a} | ${status} | ${duration}s |\n"
  if [[ "${status}" == "FAIL" ]]; then
    OVERALL_FAIL=1
    add_failed_step "Endpoint Probes"
    log_line ""
    log_line "### Endpoint Probe Failure: ${name}"
    log_line ""
    log_line '```text'
    log_line "curl exit: ${curl_exit}"
    log_line "response code: ${response_code:-n/a}"
    if [[ -n "${body}" ]]; then
      log_line "${body}"
    fi
    log_line '```'
  fi
}

run_endpoint_probes() {
  local probes_start
  probes_start="$(date +%s)"

  log_line ""
  log_line "## Endpoint Probes"
  log_line ""

  probe_endpoint "Envoy Admin Ready" "http://localhost:${ENVOY_ADMIN_PORT:-9901}/ready" "200"
  probe_endpoint "Auth API Health" "http://localhost:${AUTH_API_PORT:-8081}/health" "200"
  probe_endpoint "Main API Health" "http://localhost:${MAIN_API_HEALTH_PORT:-50052}/healthz" "200"
  probe_endpoint "OPA Health" "http://localhost:${OPA_PORT:-8181}/health" "200"
  probe_endpoint "Prometheus Health" "http://localhost:${PROMETHEUS_PORT:-9090}/-/healthy" "200"
  probe_endpoint "Grafana Health" "http://localhost:${GRAFANA_PORT:-3000}/api/health" "200"

  log_line "| Name | URL | Expected | Actual | Status | Duration |"
  log_line "| --- | --- | --- | --- | --- | --- |"
  if [[ -n "${PROBE_ROWS}" ]]; then
    printf '%b' "${PROBE_ROWS}" >> "${REPORT_PATH}"
  else
    log_line "| <none> | - | - | - | FAIL | 0s |"
    OVERALL_FAIL=1
    add_failed_step "Endpoint Probes"
  fi

  local probes_end
  probes_end="$(date +%s)"
  local duration=$((probes_end - probes_start))
  if [[ "${OVERALL_FAIL}" -eq 0 ]]; then
    record_summary "Endpoint Probes" "PASS" "${duration}"
  else
    # Probe-specific failures already mark OVERALL_FAIL; summary still reflects phase status.
    if printf '%b' "${PROBE_ROWS}" | grep -q '| FAIL |'; then
      record_summary "Endpoint Probes" "FAIL" "${duration}"
    else
      record_summary "Endpoint Probes" "PASS" "${duration}"
    fi
  fi
}

run_diagnostics() {
  run_command_step "Diagnostics: docker compose ps" "docker compose -f ${COMPOSE_FILE} --env-file ${ENV_FILE} ps" 0 || true
  run_command_step "Diagnostics: docker compose logs (tail 200)" "docker compose -f ${COMPOSE_FILE} --env-file ${ENV_FILE} logs --no-color --tail=200" 0 || true
  run_command_step "Diagnostics: docker system df" "docker system df" 0 || true
}

run_final_teardown() {
  run_command_step "Final Teardown" "docker compose -f ${COMPOSE_FILE} --env-file ${ENV_FILE} down --volumes --remove-orphans" 1 || true
}

append_summary_and_verdict() {
  local finish_epoch
  finish_epoch="$(date +%s)"
  local total_duration=$((finish_epoch - start_epoch))

  log_line ""
  log_line "## Executive Summary"
  log_line ""
  log_line "| Check | Status | Duration |"
  log_line "| --- | --- | --- |"
  if [[ -n "${SUMMARY_ROWS}" ]]; then
    printf '%b' "${SUMMARY_ROWS}" >> "${REPORT_PATH}"
  fi
  log_line ""
  log_line "Total Runtime: ${total_duration}s"
  log_line ""
  log_line "## Final Verdict"
  log_line ""
  if [[ "${OVERALL_FAIL}" -eq 0 ]]; then
    log_line "**PASS**"
  else
    log_line "**FAIL**"
    log_line ""
    log_line "Failed Steps: ${FAILED_STEPS}"
  fi
}

finalize() {
  if [[ "${FINALIZED}" -eq 1 ]]; then
    return
  fi
  FINALIZED=1

  run_final_teardown
  append_summary_and_verdict

  if [[ "${OVERALL_FAIL}" -eq 0 ]]; then
    exit 0
  fi
  exit 1
}

trap finalize EXIT

append_report_header
runtime_ready=1

if ! run_preflight; then
  runtime_ready=0
fi

if [[ "${runtime_ready}" -eq 1 ]]; then
  if ! run_compose_render_and_validate; then
    runtime_ready=0
  fi
else
  skip_step "Compose Render and Validate" "Skipped because preflight failed"
fi

if [[ "${runtime_ready}" -eq 1 ]]; then
  run_clean_down || true
  if ! run_compose_up; then
    runtime_ready=0
  fi
else
  skip_step "Compose Down (full clean)" "Skipped because compose validation failed"
  skip_step "Compose Up (build)" "Skipped because compose validation failed"
fi

if [[ "${runtime_ready}" -eq 1 ]]; then
  run_readiness_checks
  run_test_suites
  run_endpoint_probes
else
  skip_step "Service Readiness" "Skipped because compose was not brought up successfully"
  skip_step "Unit Tests" "Skipped because compose was not brought up successfully"
  skip_step "Integration Tests" "Skipped because compose was not brought up successfully"
  skip_step "E2E Tests" "Skipped because compose was not brought up successfully"
  skip_step "Endpoint Probes" "Skipped because compose was not brought up successfully"
fi

run_diagnostics
