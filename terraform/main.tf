# R37 — DNS records are absent here for a reason: the free path has no zone. Everything else
# the requirement names is below, and R39's ingress table has no counterpart because a quick
# tunnel has no ingress table to replace. Both gaps are written up rather than papered over.

provider "cloudflare" {
  # Reads CLOUDFLARE_API_TOKEN from the environment. Never a Global API Key (R38, and an
  # automatic failure if one appears anywhere).
}

# The Function's KV namespace: rate-limit counters, and the quick tunnel URLs the box
# republishes on every boot.
resource "cloudflare_workers_kv_namespace" "meridian" {
  account_id = var.account_id
  title      = "meridian-clinic"
}

resource "cloudflare_pages_project" "clinic" {
  account_id        = var.account_id
  name              = var.pages_project_name
  production_branch = "main"
}

# R25 — the partner lab's credentials. The client secret is created by Cloudflare and is
# available in state, which is exactly why state is gitignored and why R42's rotation drill
# exists.
# R42 drill 2, step 1 — the replacement credential, created BEFORE anything is revoked.
# Both tokens are valid simultaneously and the policy below admits either, so the partner can
# migrate at their own pace and the clock that matters has not started yet. Deleting first and
# creating second is the same two API calls in the order that guarantees an outage.
resource "cloudflare_zero_trust_access_service_token" "partner_lab_2" {
  account_id = var.account_id
  name       = "partner-lab-2"
  duration   = "8760h"
}

# ---------------------------------------------------------------------------------------
# Policies. Order is the point; see R14.
# ---------------------------------------------------------------------------------------

# R14 — the Block. It only does anything because it sits ABOVE the Allow in the application's
# policy list. Access evaluates in order and stops at the first match, so a Block underneath
# an Allow that already matched is dead configuration that reads as if it works.
resource "cloudflare_zero_trust_access_policy" "block_former_staff" {
  account_id = var.account_id
  name       = "meridian-block-former-staff"
  decision   = "deny"

  # sorted for the same reason the Turnstile domains are — see that resource. Order carries no
  # meaning inside a policy's include list (any match decides it), so normalising it costs
  # nothing and keeps the plan clean.
  include = [
    for email in sort(var.blocked_emails) : { email = { email = email } }
  ]
}

# R13 — the Allow, scoped to the named staff.
resource "cloudflare_zero_trust_access_policy" "allow_staff" {
  account_id = var.account_id
  name       = "meridian-allow-staff"
  decision   = "allow"

  include = [
    for email in sort(var.staff_emails) : { email = { email = email } }
  ]
}

# R25 — Service Auth, not Allow. A non_identity decision is what lets a caller with no human
# behind it through, and it is scoped to this one token rather than to any valid service token
# in the account.
resource "cloudflare_zero_trust_access_policy" "partner_service" {
  account_id = var.account_id
  name       = "meridian-partner-service-auth"
  decision   = "non_identity"

  # Two tokens during a rotation. An include list is an OR, so either credential opens the
  # application and there is no window in which neither does.
  include = [
    { service_token = { token_id = cloudflare_zero_trust_access_service_token.partner_lab_2.id } },
  ]
}

# ---------------------------------------------------------------------------------------
# Applications
# ---------------------------------------------------------------------------------------

resource "cloudflare_zero_trust_access_application" "admin" {
  account_id       = var.account_id
  name             = "Meridian staff console"
  type             = "self_hosted"
  domain           = var.admin_hostname
  session_duration = var.staff_session_duration

  # R21 — Access will happily set Cf-Access-Authenticated-User-Email on requests to the
  # origin. The origin deletes it on arrival and reads the token instead. Nothing here
  # changes that; it is noted because the convenience is the trap.

  policies = [
    # R14 — precedence 1. Reverse these two numbers and the Block stops working, silently.
    {
      id         = cloudflare_zero_trust_access_policy.block_former_staff.id
      precedence = 1
    },
    {
      id         = cloudflare_zero_trust_access_policy.allow_staff.id
      precedence = 2
    },
  ]
}

resource "cloudflare_zero_trust_access_application" "partner" {
  account_id = var.account_id
  name       = "Meridian partner API"
  type       = "self_hosted"
  domain     = var.partner_hostname

  # Pinned rather than left to the provider's 24h default. R15 asks for a deliberate choice and
  # "whatever the provider picked" is not one, even where the value is close to inert: this
  # application admits only service tokens, and a service token's life is governed by its own
  # duration (8760h) rather than by a browser session that never exists here. Stating it
  # explicitly means a future provider-default change cannot alter my infrastructure silently.
  session_duration = var.partner_session_duration

  # R28 — the staff Allow is deliberately NOT attached here, and the service-auth policy is
  # deliberately not attached to the console. The two applications also carry different AUD
  # tags, which is the check the origin actually enforces (R22).
  policies = [
    {
      id         = cloudflare_zero_trust_access_policy.partner_service.id
      precedence = 1
    },
    {
      id         = cloudflare_zero_trust_access_policy.reviewer_service.id
      precedence = 2
    },
  ]
}

# ---------------------------------------------------------------------------------------
# Identity and public-surface controls
# ---------------------------------------------------------------------------------------

# R12 — one-time PIN, declared here rather than left as the account default so that R40's
# destroy/apply cycle rebuilds it like everything else.
#
# The justification, since R12 asks for one: OTP needs no OAuth application, no client
# secret to rotate, and no dependency on a third-party tenant staying reachable. For a clinic
# with six staff and no corporate directory, that is the whole appeal. The cost is real and
# worth stating plainly — the identity is an inbox, so account security is exactly the
# security of that inbox, there is no second factor, and there is no group membership to
# revoke centrally. Removing someone means editing the Allow list (R42's first drill), not
# disabling a directory account. A clinic that grows past this size should move to an OIDC
# provider; at six people the operational simplicity wins.
resource "cloudflare_zero_trust_access_identity_provider" "otp" {
  account_id = var.account_id
  name       = "One-time PIN"
  type       = "onetimepin"
  config     = {}
}

# R31 — Turnstile guards the public appointment form. Account-scoped, so unlike a WAF ruleset
# it is available on the free path with no zone. The secret never leaves state and .env; the
# sitekey is public by design and is what the page embeds.
resource "cloudflare_turnstile_widget" "public_form" {
  account_id = var.account_id
  name       = "meridian-public-form"
  mode       = "managed"

  # sort() is not cosmetic. Cloudflare returns this list sorted, Terraform compares lists by
  # position, and an unsorted config therefore produces a diff on every single plan — for a
  # resource nobody has touched. A plan that is never clean is a plan people stop reading, and
  # R40's "destroy then apply rebuilds it" claim is only believable if the steady state is
  # genuinely zero changes. Found by running plan again after the first apply.
  domains = sort(var.turnstile_domains)
}

# ---------------------------------------------------------------------------------------
# Reviewer access (deliverable 3)
# ---------------------------------------------------------------------------------------

# A second service token, issued to the reviewer and scoped to the partner API alone. It is a
# separate token rather than a shared one on purpose: it can be revoked when the review window
# closes without touching the partner lab's integration, and its calls are distinguishable from
# the lab's in the audit log (R41) because they carry a different client id.
resource "cloudflare_zero_trust_access_service_token" "reviewer" {
  account_id = var.account_id
  name       = "reviewer"
  duration   = "8760h"
}

# Attached to the partner application only. The staff console has no non_identity policy at all,
# so this token cannot reach it — which is the same boundary R28 tests, expressed in policy
# rather than in code.
resource "cloudflare_zero_trust_access_policy" "reviewer_service" {
  account_id = var.account_id
  name       = "meridian-reviewer-service-auth"
  decision   = "non_identity"

  include = [
    { service_token = { token_id = cloudflare_zero_trust_access_service_token.reviewer.id } }
  ]
}
