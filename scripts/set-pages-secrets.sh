#!/usr/bin/env bash
# Pushes the Function's two secrets into the Pages project, for both environments.
#
# THE ORDER MATTERS AND IT COST ME AN HOUR. Pages binds secrets to a deployment at DEPLOY time,
# not at request time. Setting a secret after deploying leaves the running code holding whatever
# the binding was when it was built — for a secret that did not exist yet, an empty string. The
# symptom is `error code: 1101` on every request and, in the deployment tail,
# `DataError: Imported HMAC key length (0)`. Nothing in that names the cause.
#
# So: run this, THEN deploy. Never the other way round.
#
# The values are read from .env (0600, gitignored) and piped on stdin, so neither one ever
# appears as a command-line argument, in shell history, or in `ps` output.
set -euo pipefail

cd "$(dirname "$0")/.."

PROJECT="meridian-clinic"
WRANGLER="./node_modules/.bin/wrangler"

if [[ ! -f .env ]]; then
  echo "set-pages-secrets: .env not found" >&2
  exit 1
fi

CLOUDFLARE_API_TOKEN="$(sed -n 's/^CF_API_TOKEN=//p' .env)"
export CLOUDFLARE_API_TOKEN

put() {
  local name="$1" env="$2" value
  value="$(sed -n "s/^${name}=//p" .env)"
  if [[ -z "${value}" ]]; then
    echo "set-pages-secrets: ${name} is empty in .env" >&2
    exit 1
  fi
  printf '%s' "${value}" | "${WRANGLER}" pages secret put "${name}" \
    --project-name "${PROJECT}" --env "${env}" >/dev/null
  echo "  ${name} -> ${env} (${#value} chars)"
}

# Both environments. The staff. and api. hostnames are PREVIEW aliases — Pages serves those from
# preview deployments, which carry the preview environment's bindings. Setting only production
# leaves two of the three surfaces with empty secrets, and they fail exactly like the 1101 above.
for env in production preview; do
  echo "set-pages-secrets: ${env}"
  put EDGE_HMAC_SECRET "${env}"
  put TURNSTILE_SECRET "${env}"
done

echo "set-pages-secrets: done — now deploy, in that order"
