#!/usr/bin/env bash
# Rewrites the Terraform-derived values in .env from `terraform output`.
#
# Why this exists: R40 requires that `terraform destroy` followed by `terraform apply` rebuilds
# the system. That cycle changes SEVEN values the running system depends on — a new KV namespace
# id, two new Access AUD tags, two new service-token client ids, and a new Turnstile keypair.
# Every one of them is a value you would otherwise copy out of a dashboard by hand, at the exact
# moment you are least able to afford a typo. A wrong AUD does not fail loudly; it produces
# `wrong_audience` on every request, which reads as a broken deployment rather than a stale
# config.
#
# So the rebuild reads them out of the state that just created them. The values are identifiers,
# not secrets — except the Turnstile secret, which is why .env is 0600 and gitignored.
#
# Run from anywhere:  ./scripts/sync-env-from-terraform.sh
set -euo pipefail

cd "$(dirname "$0")/.."

if [[ ! -f .env ]]; then
  echo "sync-env: .env not found" >&2
  exit 1
fi

# tf.sh is the only path to the Cloudflare API — it loads the token from .env so the token is
# never an argument, never in shell history, and never in `ps` output.
tf() { (cd terraform && ./tf.sh "$@"); }

set_key() {
  local key="$1" value="$2"
  if [[ -z "${value}" ]]; then
    echo "sync-env: ${key} came back empty from terraform output — refusing to write it" >&2
    exit 1
  fi
  if grep -q "^${key}=" .env; then
    # The value is written with a literal-safe delimiter; these are hex ids and base64-ish
    # keys, but | is still safer than / for anything Cloudflare might return.
    python3 - "$key" "$value" <<'PY'
import sys
key, value = sys.argv[1], sys.argv[2]
lines = open('.env').read().split('\n')
out = [f'{key}={value}' if line.startswith(f'{key}=') else line for line in lines]
open('.env', 'w').write('\n'.join(out))
PY
  else
    printf '%s=%s\n' "${key}" "${value}" >> .env
  fi
  echo "  ${key} <- ${#value} chars"
}

echo "sync-env: reading terraform outputs"

KV_ID="$(tf output -raw kv_namespace_id)"
AUD_ADMIN="$(tf output -raw access_aud_admin)"
AUD_PARTNER="$(tf output -raw access_aud_partner)"
TURNSTILE_SITEKEY="$(tf output -raw turnstile_sitekey)"
TURNSTILE_SECRET="$(tf output -raw turnstile_secret)"
PARTNER_ID="$(tf output -raw partner_client_id_2)"
REVIEWER_ID="$(tf output -raw reviewer_client_id)"

# R22 — the two AUD tags must differ. If a future refactor ever pointed both applications at one
# tag, every Access token in the team would open every application, and the origin's audience
# check would pass while enforcing nothing. Cheap to assert, catastrophic to miss.
if [[ "${AUD_ADMIN}" == "${AUD_PARTNER}" ]]; then
  echo "sync-env: the two AUD tags are identical — that is the R22 vulnerability, refusing to write" >&2
  exit 1
fi

set_key CF_KV_NAMESPACE_ID "${KV_ID}"
set_key ACCESS_AUD_ADMIN "${AUD_ADMIN}"
set_key ACCESS_AUD_PARTNER "${AUD_PARTNER}"
set_key TURNSTILE_SITE_KEY "${TURNSTILE_SITEKEY}"
set_key TURNSTILE_SECRET "${TURNSTILE_SECRET}"

# The origin checks the client id as well as the token's signature: a valid Cloudflare service
# token is not by itself enough to reach the partner API. Both machine callers go in here.
set_key PARTNER_CLIENT_IDS "${PARTNER_ID},${REVIEWER_ID}"

chmod 600 .env

echo "sync-env: done. Next:"
echo "  1. pnpm run pages:secrets   # Pages binds secrets at DEPLOY time — set them first"
echo "  2. pnpm run pages:deploy    # and for the staff/api preview branches"
echo "  3. restart the origin and the tunnel supervisor so both read the new .env"
