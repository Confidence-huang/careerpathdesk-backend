#!/usr/bin/env bash
# Prepare Git-ignored local secrets for the synthetic PostgreSQL and API boundary.
# Run with: bash scripts/prepare-synthetic.sh

set -euo pipefail

readonly script_directory="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
readonly repository_root="$(cd -- "$script_directory/.." && pwd -P)"
readonly runtime_directory="$repository_root/.runtime"

# --- Create the one local secret directory ---

install -d -m 0700 "$runtime_directory"

# --- Generate each missing synthetic secret without printing it ---

if [[ ! -f "$runtime_directory/postgres_password" ]]; then
  openssl rand -out "$runtime_directory/postgres_password" -hex 24
fi

if [[ ! -f "$runtime_directory/synthetic_account_password" ]]; then
  openssl rand -out "$runtime_directory/synthetic_account_password" -base64 36
fi

if [[ ! -f "$runtime_directory/access_token_private_key.pem" ]]; then
  openssl genpkey -algorithm Ed25519 -out "$runtime_directory/access_token_private_key.pem" 2>/dev/null
fi

chmod 0600 \
  "$runtime_directory/postgres_password" \
  "$runtime_directory/synthetic_account_password" \
  "$runtime_directory/access_token_private_key.pem"

echo "PASS: prepared Git-ignored synthetic runtime files"
