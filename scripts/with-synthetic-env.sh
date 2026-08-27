#!/usr/bin/env bash
# Run one command inside the explicit CareerPathDesk synthetic configuration boundary.
# Example: bash scripts/with-synthetic-env.sh go test ./... -count=1

set -euo pipefail

readonly script_directory="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
readonly repository_root="$(cd -- "$script_directory/.." && pwd -P)"
readonly runtime_directory="$repository_root/.runtime"

if (( $# == 0 )); then
  echo "FAIL: a command is required" >&2
  exit 1
fi

if [[ ! -f "$runtime_directory/postgres_password" ]]; then
  echo "FAIL: run scripts/prepare-synthetic.sh first" >&2
  exit 1
fi

# --- Export only the reviewed synthetic identities ---

export CAREERPATH_RUNTIME_MODE="synthetic"
export CAREERPATH_HTTP_ADDR="127.0.0.1:8180"
export CAREERPATH_DATABASE_URL="postgres://careerpathdesk@127.0.0.1:55432/careerpathdesk_synthetic?sslmode=disable"
export CAREERPATH_DATABASE_PASSWORD_FILE="$runtime_directory/postgres_password"
export CAREERPATH_EXPECTED_SCHEMA_VERSION="9"
export CAREERPATH_SEED_PROFILE="synthetic-foundation-v1"
export CAREERPATH_SYNTHETIC_ACCOUNT_PASSWORD_FILE="$runtime_directory/synthetic_account_password"
export CAREERPATH_PUBLIC_ORIGIN="http://127.0.0.1:5173"
export CAREERPATH_ACCESS_TOKEN_PRIVATE_KEY_FILE="$runtime_directory/access_token_private_key.pem"
export CAREERPATH_TEST_DATABASE_URL="$CAREERPATH_DATABASE_URL"
export CAREERPATH_TEST_DATABASE_PASSWORD_FILE="$CAREERPATH_DATABASE_PASSWORD_FILE"

exec "$@"
