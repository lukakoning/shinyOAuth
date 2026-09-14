#!/usr/bin/env bash
set -euo pipefail

# Run an isolated copy of the real runner with controlled external commands.
RUNNER_LOG="$2"
RUNNER_PULL_FAILURES="$3"
RUNNER_START_RC="$4"
RUNNER_TEST_RC="$5"

docker() {
  printf 'docker %s\n' "$*" >> "$RUNNER_LOG"
  case "$*" in
    'compose pull --policy missing keycloak')
      local attempt=0
      if [[ -f "${RUNNER_LOG}.pulls" ]]; then
        read -r attempt < "${RUNNER_LOG}.pulls"
      fi
      attempt=$((attempt + 1))
      printf '%s\n' "$attempt" > "${RUNNER_LOG}.pulls"
      if ((attempt <= RUNNER_PULL_FAILURES)); then
        echo 'received unexpected HTTP status: 504 Gateway Time-out' >&2
        return 42
      fi
      ;;
    'compose up -d --pull never') return "$RUNNER_START_RC" ;;
    'compose logs --no-color') echo 'synthetic Docker logs' ;;
    'compose down -v') ;;
    *) echo "Unexpected Docker command: $*" >&2; return 99 ;;
  esac
}

curl() { return 0; }
openssl() { return 0; }
sleep() { printf 'sleep %s\n' "$*" >> "$RUNNER_LOG"; }
Rscript() {
  printf 'Rscript %s\n' "$*" >> "$RUNNER_LOG"
  return "$RUNNER_TEST_RC"
}

source "$1"
