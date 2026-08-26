#!/usr/bin/env bash
# R38/R40 — the only way this project talks to Cloudflare's API.
#
# It reads the scoped API token out of ../.env (mode 600, gitignored) and exports it as
# CLOUDFLARE_API_TOKEN for the provider. The token never appears in a shell history, a
# terraform file, or an argument list. A Global API Key is never accepted here — the provider
# is not configured to read one, and R38 makes its presence anywhere an automatic failure.
#
#   ./tf.sh plan
#   ./tf.sh apply
#   ./tf.sh destroy      # then ./tf.sh apply — R40, no dashboard click in between
set -euo pipefail

cd "$(dirname "$0")"

if [[ ! -f ../.env ]]; then
  echo "tf.sh: ../.env not found — copy .env.example and fill it in" >&2
  exit 1
fi

# shellcheck disable=SC2155
export CLOUDFLARE_API_TOKEN="$(sed -n 's/^CF_API_TOKEN=//p' ../.env)"

if [[ -z "${CLOUDFLARE_API_TOKEN}" ]]; then
  echo "tf.sh: CF_API_TOKEN is empty in ../.env" >&2
  exit 1
fi

exec terraform "$@"
