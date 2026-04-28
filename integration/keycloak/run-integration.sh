#!/usr/bin/env bash
set -euo pipefail

# One-shot script: start Keycloak (Docker), wait until ready, run integration test, tear down.
# Exits with the test's exit code.

# Resolve important paths
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"
COMPOSE_DIR="${SCRIPT_DIR}"
TLS_PREPARE_SCRIPT="${SCRIPT_DIR}/prepare-tls.sh"
TLS_DIR="${SCRIPT_DIR}/tls"

to_host_path() {
  if command -v cygpath >/dev/null 2>&1; then
    cygpath -m "$1"
  else
    printf '%s' "$1"
  fi
}

# Config
ISSUER_URL="https://localhost:8443/realms/shinyoauth"
DISCOVERY_URL="${ISSUER_URL}/.well-known/openid-configuration"
WAIT_TIMEOUT_SEC="120"   # total wait time
WAIT_INTERVAL_SEC="2"    # poll interval

CA_CERT="${TLS_DIR}/ca-cert.pem"
CLIENT_CERT="${TLS_DIR}/client-cert.pem"
CLIENT_KEY="${TLS_DIR}/client-key.pem"
ATTACKER_CERT="${TLS_DIR}/attacker-cert.pem"
ATTACKER_KEY="${TLS_DIR}/attacker-key.pem"
ROGUE_CLIENT_CERT="${TLS_DIR}/rogue-client-cert.pem"
ROGUE_CLIENT_KEY="${TLS_DIR}/rogue-client-key.pem"

CURL_TLS_FLAGS=(--cacert "$CA_CERT")
if curl --help all 2>/dev/null | grep -q -- '--ssl-no-revoke'; then
  CURL_TLS_FLAGS+=(--ssl-no-revoke)
fi

# Verify docker is available
if ! command -v docker >/dev/null 2>&1; then
  echo "Error: docker is not installed or not on PATH" >&2
  exit 127
fi

if ! command -v curl >/dev/null 2>&1; then
  echo "Error: curl is not installed or not on PATH" >&2
  exit 127
fi

if ! command -v openssl >/dev/null 2>&1; then
  echo "Error: openssl is not installed or not on PATH" >&2
  exit 127
fi

cleanup() {
  local rc=$?
  echo "\n[run-integration] Bringing down Keycloak (docker compose down -v)" >&2
  (cd "$COMPOSE_DIR" && docker compose down -v >/dev/null 2>&1 || true)
  exit $rc
}
trap cleanup EXIT INT TERM

echo "[run-integration] Preparing TLS materials..." >&2
# Invoke via bash so this works even when the executable bit is not preserved.
"${BASH:-bash}" "$TLS_PREPARE_SCRIPT"

# Start services
echo "[run-integration] Starting Keycloak via docker compose..." >&2
(cd "$COMPOSE_DIR" && docker compose up -d)

# Wait for readiness by polling discovery
echo "[run-integration] Waiting for discovery at ${DISCOVERY_URL} ..." >&2
start_ts=$(date +%s)
while true; do
  # The outer polling loop already retries discovery until readiness, so keep
  # the inner curl invocation portable across older builds by avoiding
  # --retry-all-errors (which is unavailable on some versions and does nothing
  # here unless paired with --retry).
  if curl \
    "${CURL_TLS_FLAGS[@]}" \
    -fsS "$DISCOVERY_URL" >/dev/null 2>&1; then
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
  export SHINYOAUTH_KEYCLOAK_CA_FILE="$(to_host_path "$CA_CERT")"
  export SHINYOAUTH_KEYCLOAK_CLIENT_CERT_FILE="$(to_host_path "$CLIENT_CERT")"
  export SHINYOAUTH_KEYCLOAK_CLIENT_KEY_FILE="$(to_host_path "$CLIENT_KEY")"
  export SHINYOAUTH_KEYCLOAK_ATTACKER_CERT_FILE="$(to_host_path "$ATTACKER_CERT")"
  export SHINYOAUTH_KEYCLOAK_ATTACKER_KEY_FILE="$(to_host_path "$ATTACKER_KEY")"
  export SHINYOAUTH_KEYCLOAK_ROGUE_CLIENT_CERT_FILE="$(to_host_path "$ROGUE_CLIENT_CERT")"
  export SHINYOAUTH_KEYCLOAK_ROGUE_CLIENT_KEY_FILE="$(to_host_path "$ROGUE_CLIENT_KEY")"
  export CURL_CA_BUNDLE="$SHINYOAUTH_KEYCLOAK_CA_FILE"
  export CURL_SSL_BACKEND="${CURL_SSL_BACKEND:-openssl}"
  Rscript -e "pkgload::load_all('.') ; testthat::test_dir('integration/keycloak')"
)
TEST_RC=$?

if [ $TEST_RC -eq 0 ]; then
  echo "[run-integration] Tests passed." >&2
else
  echo "[run-integration] Tests failed with exit code $TEST_RC" >&2
fi

exit $TEST_RC
