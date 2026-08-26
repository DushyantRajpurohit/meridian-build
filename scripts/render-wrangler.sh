#!/usr/bin/env bash
# Renders pages/wrangler.toml from the template, substituting the KV namespace id that
# Terraform created.
#
# Why this exists rather than a committed wrangler.toml with the id in it: R40 requires that
# `terraform destroy` followed by `terraform apply` rebuilds the system. That cycle creates a
# NEW KV namespace with a new id. A committed id would survive the destroy, still look correct,
# and bind the Function to a namespace that no longer exists — a stale value that fails at
# runtime rather than at deploy. Generating it means the id can only ever come from the
# infrastructure that actually exists right now.
#
# The id is not a secret; it is an identifier. Keeping it out of git is about staleness, not
# confidentiality.
set -euo pipefail

cd "$(dirname "$0")/.."

if [[ ! -f .env ]]; then
  echo "render-wrangler: .env not found" >&2
  exit 1
fi

KV_ID="$(sed -n 's/^CF_KV_NAMESPACE_ID=//p' .env)"

if [[ -z "${KV_ID}" ]]; then
  echo "render-wrangler: CF_KV_NAMESPACE_ID is empty in .env — run 'terraform apply' first" >&2
  exit 1
fi

sed "s|REPLACED_BY_TERRAFORM|${KV_ID}|" pages/wrangler.template.toml > pages/wrangler.toml
echo "render-wrangler: pages/wrangler.toml written, KV binding -> ${KV_ID}"
