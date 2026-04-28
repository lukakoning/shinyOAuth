#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TLS_DIR="${SCRIPT_DIR}/tls"

CA_CERT="${TLS_DIR}/ca-cert.pem"
CA_KEY="${TLS_DIR}/ca-key.pem"
SERVER_CERT="${TLS_DIR}/server-cert.pem"
SERVER_KEY="${TLS_DIR}/server-key.pem"
CLIENT_CERT="${TLS_DIR}/client-cert.pem"
CLIENT_KEY="${TLS_DIR}/client-key.pem"
ATTACKER_CERT="${TLS_DIR}/attacker-cert.pem"
ATTACKER_KEY="${TLS_DIR}/attacker-key.pem"
ROGUE_CA_CERT="${TLS_DIR}/rogue-ca-cert.pem"
ROGUE_CA_KEY="${TLS_DIR}/rogue-ca-key.pem"
ROGUE_CLIENT_CERT="${TLS_DIR}/rogue-client-cert.pem"
ROGUE_CLIENT_KEY="${TLS_DIR}/rogue-client-key.pem"
SERIAL_FILE="${TLS_DIR}/ca-cert.srl"
ROGUE_SERIAL_FILE="${TLS_DIR}/rogue-ca-cert.srl"

required_files=(
  "$CA_CERT"
  "$CA_KEY"
  "$SERVER_CERT"
  "$SERVER_KEY"
  "$CLIENT_CERT"
  "$CLIENT_KEY"
  "$ATTACKER_CERT"
  "$ATTACKER_KEY"
  "$ROGUE_CA_CERT"
  "$ROGUE_CA_KEY"
  "$ROGUE_CLIENT_CERT"
  "$ROGUE_CLIENT_KEY"
  "$SERIAL_FILE"
  "$ROGUE_SERIAL_FILE"
)

all_tls_files_exist=true
for tls_file in "${required_files[@]}"; do
  if [[ ! -f "$tls_file" ]]; then
    all_tls_files_exist=false
    break
  fi
done

if [[ "$all_tls_files_exist" == true ]]; then
  echo "[prepare-tls] Using existing TLS materials in ${TLS_DIR}" >&2
  exit 0
fi

run_openssl() {
  MSYS_NO_PATHCONV=1 openssl "$@"
}

mkdir -p "$TLS_DIR"
cd "$TLS_DIR"

CA_CERT="ca-cert.pem"
CA_KEY="ca-key.pem"
SERVER_CERT="server-cert.pem"
SERVER_KEY="server-key.pem"
CLIENT_CERT="client-cert.pem"
CLIENT_KEY="client-key.pem"
ATTACKER_CERT="attacker-cert.pem"
ATTACKER_KEY="attacker-key.pem"
ROGUE_CA_CERT="rogue-ca-cert.pem"
ROGUE_CA_KEY="rogue-ca-key.pem"
ROGUE_CLIENT_CERT="rogue-client-cert.pem"
ROGUE_CLIENT_KEY="rogue-client-key.pem"

SERVER_EXT="server-ext.cnf"
CLIENT_EXT="client-ext.cnf"
SERIAL_FILE="ca-cert.srl"
ROGUE_SERIAL_FILE="rogue-ca-cert.srl"

cat > "$SERVER_EXT" <<'EOF'
subjectAltName=DNS:localhost,IP:127.0.0.1
basicConstraints=CA:FALSE
keyUsage=digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
EOF

cat > "$CLIENT_EXT" <<'EOF'
basicConstraints=CA:FALSE
keyUsage=digitalSignature,keyEncipherment
extendedKeyUsage=clientAuth
EOF

generate_ca() {
  local cert_path="$1"
  local key_path="$2"
  local subject="$3"

  run_openssl req \
    -x509 \
    -newkey rsa:2048 \
    -sha256 \
    -days 3650 \
    -nodes \
    -keyout "$key_path" \
    -out "$cert_path" \
    -subj "$subject" \
    -addext "basicConstraints=critical,CA:TRUE" \
    -addext "keyUsage=critical,keyCertSign,cRLSign" \
    >/dev/null 2>&1
}

generate_leaf() {
  local cert_path="$1"
  local key_path="$2"
  local csr_path="$3"
  local subject="$4"
  local ca_cert_path="$5"
  local ca_key_path="$6"
  local serial_path="$7"
  local ext_path="$8"
  local serial_args=()

  run_openssl req \
    -new \
    -newkey rsa:2048 \
    -nodes \
    -keyout "$key_path" \
    -out "$csr_path" \
    -subj "$subject" \
    >/dev/null 2>&1

  if [[ -f "$serial_path" ]]; then
    serial_args=(-CAserial "$serial_path")
  else
    serial_args=(-CAcreateserial -CAserial "$serial_path")
  fi

  run_openssl x509 \
    -req \
    -in "$csr_path" \
    -CA "$ca_cert_path" \
    -CAkey "$ca_key_path" \
    "${serial_args[@]}" \
    -out "$cert_path" \
    -days 3650 \
    -sha256 \
    -extfile "$ext_path" \
    >/dev/null 2>&1

  rm -f "$csr_path"
}

generate_ca \
  "$CA_CERT" \
  "$CA_KEY" \
  "/C=US/ST=NA/L=Local/O=shinyOAuth/OU=Tests/CN=shinyOAuth Test CA"

generate_leaf \
  "$SERVER_CERT" \
  "$SERVER_KEY" \
  "server.csr" \
  "/C=US/ST=NA/L=Local/O=shinyOAuth/OU=Tests/CN=localhost" \
  "$CA_CERT" \
  "$CA_KEY" \
  "$SERIAL_FILE" \
  "$SERVER_EXT"

generate_leaf \
  "$CLIENT_CERT" \
  "$CLIENT_KEY" \
  "client.csr" \
  "/C=US/ST=NA/L=Local/O=shinyOAuth/OU=Tests/CN=shiny-mtls-client" \
  "$CA_CERT" \
  "$CA_KEY" \
  "$SERIAL_FILE" \
  "$CLIENT_EXT"

generate_leaf \
  "$ATTACKER_CERT" \
  "$ATTACKER_KEY" \
  "attacker.csr" \
  "/C=US/ST=NA/L=Local/O=shinyOAuth/OU=Tests/CN=shiny-mtls-attacker" \
  "$CA_CERT" \
  "$CA_KEY" \
  "$SERIAL_FILE" \
  "$CLIENT_EXT"

generate_ca \
  "$ROGUE_CA_CERT" \
  "$ROGUE_CA_KEY" \
  "/C=US/ST=NA/L=Local/O=shinyOAuth/OU=Tests/CN=shinyOAuth Rogue CA"

generate_leaf \
  "$ROGUE_CLIENT_CERT" \
  "$ROGUE_CLIENT_KEY" \
  "rogue-client.csr" \
  "/C=US/ST=NA/L=Local/O=shinyOAuth/OU=Tests/CN=shiny-mtls-client" \
  "$ROGUE_CA_CERT" \
  "$ROGUE_CA_KEY" \
  "$ROGUE_SERIAL_FILE" \
  "$CLIENT_EXT"

echo "[prepare-tls] Wrote TLS materials to ${TLS_DIR}" >&2
