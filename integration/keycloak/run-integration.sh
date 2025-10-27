#!/usr/bin/env bash
set -euo pipefail

# One-shot script: start Keycloak (Docker), wait until ready, run integration test, tear down.
# Exits with the test's exit code.

# Resolve important paths
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"
COMPOSE_DIR="${SCRIPT_DIR}"

# Config
ISSUER_URL="http://localhost:8080/realms/shinyoauth"
DISCOVERY_URL="${ISSUER_URL}/.well-known/openid-configuration"
WAIT_TIMEOUT_SEC="120"   # total wait time
WAIT_INTERVAL_SEC="2"    # poll interval

# Verify docker is available
if ! command -v docker >/dev/null 2>&1; then
  echo "Error: docker is not installed or not on PATH" >&2
  exit 127
fi

cleanup() {
  local rc=$?
  echo "\n[run-integration] Bringing down Keycloak (docker compose down -v)" >&2
  (cd "$COMPOSE_DIR" && docker compose down -v >/dev/null 2>&1 || true)
  exit $rc
}
trap cleanup EXIT INT TERM

# Start services
echo "[run-integration] Starting Keycloak via docker compose..." >&2
(cd "$COMPOSE_DIR" && docker compose up -d)

# Wait for readiness by polling discovery
echo "[run-integration] Waiting for discovery at ${DISCOVERY_URL} ..." >&2
start_ts=$(date +%s)
while true; do
  if curl -fsS "$DISCOVERY_URL" >/dev/null 2>&1; then
    echo "[run-integration] Discovery is reachable." >&2
    break
  fi
  now=$(date +%s)
  elapsed=$(( now - start_ts ))
  if [ "$elapsed" -ge "$WAIT_TIMEOUT_SEC" ]; then
    echo "[run-integration] Timeout waiting for Keycloak readiness after ${WAIT_TIMEOUT_SEC}s" >&2
    echo "[run-integration] Recent logs:" >&2
    (cd "$COMPOSE_DIR" && docker compose logs --no-color --tail=200 keycloak || true) >&2
    exit 1
  fi
  sleep "$WAIT_INTERVAL_SEC"
done

# Run all integration tests from this folder using testthat::test_dir
echo "[run-integration] Running integration tests (SHINYOAUTH_INT=1) ..." >&2
(
  cd "$REPO_DIR"
  export SHINYOAUTH_INT=1
  # Ensure tests don't behave as if running on CRAN; needed for {shinytest2} which skips on CRAN
  export NOT_CRAN=true
  Rscript -e "pkgload::load_all('.') ; testthat::test_dir('integration/keycloak')"
)
TEST_RC=$?

if [ $TEST_RC -eq 0 ]; then
  echo "[run-integration] Tests passed." >&2
else
  echo "[run-integration] Tests failed with exit code $TEST_RC" >&2
fi

exit $TEST_RC
